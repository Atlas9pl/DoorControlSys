#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <LiquidCrystal.h>
#include <Keypad.h>
#include <ESP32Servo.h>
#include <time.h>
#include <TOTP.h> 

// ==========================================
// PIN DEFINITIONS & HARDWARE SETUP
// ==========================================

#define SS_PIN  5
#define RST_PIN 255 // 255 tells the library this pin is unused (Hardwired to 3.3V)
MFRC522 mfrc522(SS_PIN, RST_PIN);

LiquidCrystal lcd(22, 21, 17, 16, 2, 15);

const byte ROWS = 4;
const byte COLS = 3;
char keys[ROWS][COLS] = {
  {'1','2','3'},
  {'4','5','6'},
  {'7','8','9'},
  {'*','0','#'}
};
byte rowPins[ROWS] = {13, 12, 14, 27};
byte colPins[COLS] = {26, 25, 4}; // Replaced missing Pin 0 with newly freed Pin 4
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

const int SERVO_PIN = 32;
Servo doorServo;

const int BUZZER_PIN = 33;

// ==========================================
// TOTP & TIME CONFIGURATION
// ==========================================
const char* ntpServer = "pool.ntp.org";
const long  gmtOffset_sec = 0; // TOTP ALWAYS uses UTC time (0 offset)
const int   daylightOffset_sec = 0;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
const unsigned long WIFI_RETRY_INTERVAL_MS = 30000;
const unsigned long TIME_SYNC_RETRY_INTERVAL_MS = 60000;
const long TOTP_STEP_SECONDS = 30;
const int8_t TOTP_ACCEPT_WINDOW_STEPS = 1;

// The Hex equivalent of the Base32 secret "GEZDGNBVGY3TQOJQ"
uint8_t hmacKey[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30};
TOTP totp = TOTP(hmacKey, 10);

enum SystemState { STATE_IDLE, STATE_KEYPAD, STATE_UNLOCK };
SystemState currentState = STATE_IDLE;

const char* ssid = "Atlas"; 
const char* password = "Zappy454";

// EXPECTS 6 DIGITS (7 characters including null terminator)
char expectedOTP[7] = "000000";       
const char masterPIN[7] = "123456";   
char enteredPIN[7];                 
byte inputIndex = 0;

unsigned long unlockStartTime = 0;
const unsigned long UNLOCK_DURATION = 5000;
bool justEnteredUnlock = false;
bool timeSynced = false;
bool useTOTPAuth = false;
unsigned long lastWiFiRetryMs = 0;
unsigned long lastTimeSyncRetryMs = 0;

// ==========================================
// FUNCTION PROTOTYPES (CRITICAL FOR PLATFORMIO)
// ==========================================
void handleIdleState();
void handleKeypadState();
void handleUnlockState();
void lcdPrint(const char* line1, const char* line2);
void updateIdleLCD();
void resetKeypadInput();
void beep(int duration);
bool syncTimeFromNTP();
bool isValidOnlineOTP(const char* pin);
void maintainWiFiAndTime();

// ==========================================
// SETUP
// ==========================================

void setup() {
  Serial.begin(115200);
  
  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  lcd.begin(16, 2);
  
  ESP32PWM::allocateTimer(0);
  doorServo.setPeriodHertz(50);
  doorServo.attach(SERVO_PIN, 500, 2400);
  doorServo.write(0); 
  
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  
  lcdPrint("Connecting to", "WiFi...");
  WiFi.begin(ssid, password);
  unsigned long wifiStart = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - wifiStart < WIFI_CONNECT_TIMEOUT_MS)) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi Connected!");
  } else {
    Serial.println("\nWiFi not connected. Continuing in offline mode.");
  }

  // Enforce strict UTC Timezone 
  setenv("TZ", "UTC0", 1);
  tzset();

  if (WiFi.status() == WL_CONNECTED) {
    timeSynced = syncTimeFromNTP();
  } else {
    timeSynced = false;
  }
  
  updateIdleLCD();
}

void loop() {
  switch (currentState) {
    case STATE_IDLE: handleIdleState(); break;
    case STATE_KEYPAD: handleKeypadState(); break;
    case STATE_UNLOCK: handleUnlockState(); break;
  }
}

void handleIdleState() {
  maintainWiFiAndTime();

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) return;

  beep(100); 
  
  if (timeSynced) {
    // 1. Get current UTC Time
    time_t now;
    time(&now);
    
    // DEBUG: Print the Unix Timestamp
    Serial.print("Current UTC Unix Time: ");
    Serial.println((long)now);
    
    // 2. Generate the full 6-digit TOTP code (explicitly cast to 32-bit long)
    char* fullCode = totp.getCode((long)now);
    
    // 3. Store the full 6 digits
    strncpy(expectedOTP, fullCode, sizeof(expectedOTP) - 1);
    expectedOTP[sizeof(expectedOTP) - 1] = '\0';
    
    Serial.print("Current Expected 6-Digit Code: ");
    Serial.println(expectedOTP);
    
    lcdPrint("Check Auth App", "Enter OTP:");
    useTOTPAuth = true;
  } else {
    strcpy(expectedOTP, masterPIN);
    lcdPrint("Offline Mode", "Use Master PIN");
    useTOTPAuth = false;
  }
  
  currentState = STATE_KEYPAD;
  resetKeypadInput();
  mfrc522.PICC_HaltA(); 
}

void handleKeypadState() {
  char key = keypad.getKey();
  if (key) {
    beep(50); 
    if (key == '*' || key == '#') {
      resetKeypadInput();
      lcdPrint("Enter PIN:", "");
      return;
    }
    enteredPIN[inputIndex] = key;
    enteredPIN[inputIndex + 1] = '\0'; 
    lcd.setCursor(inputIndex, 1);
    lcd.print('*'); 
    inputIndex++;

    // NOW WAITS FOR 6 DIGITS
    if (inputIndex == 6) {
      bool isAuthorized = false;
      if (useTOTPAuth) {
        isAuthorized = isValidOnlineOTP(enteredPIN);
      } else {
        isAuthorized = (strcmp(enteredPIN, expectedOTP) == 0);
      }

      if (isAuthorized) {
        currentState = STATE_UNLOCK;
        justEnteredUnlock = true;
      } else {
        lcdPrint("Access Denied!", "Wrong PIN");
        beep(500); 
        delay(1500); 
        currentState = STATE_IDLE;
        updateIdleLCD();
      }
    }
  }
}

void handleUnlockState() {
  if (justEnteredUnlock) {
    lcdPrint("Access Granted!", "Door Unlocked.");
    doorServo.write(90); 
    unlockStartTime = millis();
    justEnteredUnlock = false;
  }
  if (millis() - unlockStartTime >= UNLOCK_DURATION) {
    doorServo.write(0); 
    currentState = STATE_IDLE;
    updateIdleLCD();
  }
}

void lcdPrint(const char* line1, const char* line2) {
  lcd.clear(); 
  lcd.setCursor(0, 0); 
  lcd.print(line1); 
  lcd.setCursor(0, 1); 
  lcd.print(line2);
}

void updateIdleLCD() {
  if (timeSynced) lcdPrint("Scan ID Card", "[Auth: TOTP]");
  else lcdPrint("Scan ID Card", "[Auth: Master]");
}

void resetKeypadInput() {
  inputIndex = 0; 
  memset(enteredPIN, 0, sizeof(enteredPIN));
}

void beep(int duration) {
  digitalWrite(BUZZER_PIN, HIGH); 
  delay(duration); 
  digitalWrite(BUZZER_PIN, LOW);
}

bool syncTimeFromNTP() {
  lcdPrint("Syncing Time...", "");
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  struct tm timeinfo;
  if (!getLocalTime(&timeinfo, 5000)) {
    Serial.println("Failed to obtain time. Falling back to master PIN.");
    return false;
  }

  Serial.println("Time synced successfully!");
  return true;
}

bool isValidOnlineOTP(const char* pin) {
  time_t now;
  time(&now);

  if (now <= 0) {
    Serial.println("Invalid system time. Rejecting OTP.");
    return false;
  }

  for (int8_t offset = -TOTP_ACCEPT_WINDOW_STEPS; offset <= TOTP_ACCEPT_WINDOW_STEPS; offset++) {
    long candidateTime = (long)now + (offset * TOTP_STEP_SECONDS);
    char* candidateCode = totp.getCode(candidateTime);
    if (strcmp(pin, candidateCode) == 0) {
      Serial.print("OTP accepted with time-step offset: ");
      Serial.println(offset);
      return true;
    }
  }

  Serial.println("OTP validation failed for all allowed time windows.");
  return false;
}

void maintainWiFiAndTime() {
  unsigned long nowMs = millis();

  if (WiFi.status() != WL_CONNECTED) {
    if (nowMs - lastWiFiRetryMs >= WIFI_RETRY_INTERVAL_MS) {
      lastWiFiRetryMs = nowMs;
      Serial.println("WiFi disconnected. Retrying...");
      WiFi.reconnect();
    }
    return;
  }

  if (!timeSynced && nowMs - lastTimeSyncRetryMs >= TIME_SYNC_RETRY_INTERVAL_MS) {
    lastTimeSyncRetryMs = nowMs;
    Serial.println("WiFi restored. Attempting time sync...");
    timeSynced = syncTimeFromNTP();
    updateIdleLCD();
  }
}
