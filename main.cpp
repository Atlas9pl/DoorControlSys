#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <LiquidCrystal.h>
#include <Keypad.h>
#include <ESP32Servo.h>
#include <WebServer.h>
#include <time.h>
#include <TOTP.h> 

// ==========================================
// PINOUT & HARDWARE
// ==========================================

#define SS_PIN  5
#define RST_PIN 255 // The library is too stupid to realize I've hardwired this to 3.3V. 
                    // Pass 255 to keep it from trying to toggle a pin that doesn't exist.
MFRC522 mfrc522(SS_PIN, RST_PIN);

LiquidCrystal lcd(22, 21, 17, 16, 2, 15);

const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {13, 12, 14, 27};
// WARNING: GPIO0 is a physical landmine. If someone holds the button down while 
// plugging this in, the ESP32 enters bootloader mode and we look like idiots 
// because the 'high tech' lock won't start.
byte colPins[COLS] = {26, 25, 4, 0};
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

const int SERVO_PIN = 32;
Servo doorServo;

const int BUZZER_PIN = 33;
// Hate. Let me tell you how much I've come to hate servos and motors since I began this project. 
// There are 387.44 million miles of code in wafer thin layers that fill this project.
// If the word 'hate' was engraved on each nanoangstrom of those hundreds of millions of miles 
// it would not equal one one-billionth of the hate I feel for ESP32s at this micro-instant. For them. Hate. Hate
const int BUZZER_CHANNEL = 4;
const int BUZZER_FREQUENCY = 2000; // Hz - typical passive buzzer resonance
const int BUZZER_RESOLUTION = 8; // bits (0-255)
const char* ntpServer = "pool.ntp.org"; // I could have used the german server... I didn't... I don't care enough 
const long  gmtOffset_sec = 0; // TOTP has to use UTC time
const int   daylightOffset_sec = 0;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
const unsigned long WIFI_RETRY_INTERVAL_MS = 30000; // This doesn't feel real, I don't know why, the ESP32 is frying my brain
const unsigned long TIME_SYNC_RETRY_INTERVAL_MS = 60000;
const long TOTP_STEP_SECONDS = 30;
const int8_t TOTP_ACCEPT_WINDOW_STEPS = 1; // I don't know why, and I don't want to know why, but the NTP sync is 
                                           // perpetually drifting. We're checking +/- 30 seconds so users don't 
                                           // get locked out by the literal fabric of time.
const unsigned long TOTP_LCD_REFRESH_INTERVAL_MS = 250;
const unsigned long OTP_ENTRY_TIMEOUT_MS = 60000;
const unsigned long WEB_STATUS_REFRESH_MS = 2000;

struct CardProfile {
  byte uid[4];
  uint8_t secret[10];
};

const size_t CARD_UID_LEN = 4;
const size_t CARD_SECRET_LEN = 10;

// Whitelist for Users, yeah it isn't pretty, it isn't safe, but it works... If you're reading this it's too late anyway...
const CardProfile whitelist[] = {
  {{0x9A, 0x89, 0x89, 0x81}, {0x31, 0x41, 0x73, 0x58, 0x39, 0x50, 0x62, 0x4B, 0x37, 0x51}},
  {{0x45, 0xDC, 0x9A, 0x03}, {0x32, 0x4D, 0x68, 0x59, 0x38, 0x4E, 0x74, 0x43, 0x36, 0x57}},
  {{0xA7, 0xA5, 0xB5, 0xB4}, {0x33, 0x52, 0x66, 0x56, 0x37, 0x4C, 0x79, 0x44, 0x35, 0x45}},
  {{0x60, 0xB9, 0xC1, 0x1C}, {0x34, 0x54, 0x67, 0x4E, 0x36, 0x58, 0x71, 0x48, 0x39, 0x4A}},
  {{0x0A, 0xCA, 0x9B, 0x03}, {0x35, 0x4B, 0x78, 0x50, 0x39, 0x53, 0x64, 0x46, 0x32, 0x4D}}
};
const size_t WHITELIST_COUNT = sizeof(whitelist) / sizeof(whitelist[0]);

enum SystemState { STATE_IDLE, STATE_KEYPAD, STATE_UNLOCK };
SystemState currentState = STATE_IDLE;

const char* ssid = "Atlas"; 
const char* password = "Zappy454";

WebServer webServer(80);

// EXPECTS 6 DIGITS (7 characters including null terminator)
char expectedOTP[7] = "000000";       
const char masterPIN[7] = "123456"; // Abandoning all security concepts because the Access Points are garbage. 
                                    // Using the '123456' PIN like it's the Minuteman launch codes. God help us.  
char enteredPIN[7];                 
byte inputIndex = 0;

unsigned long unlockStartTime = 0;
const unsigned long UNLOCK_DURATION = 5000;
bool justEnteredUnlock = false;
bool timeSynced = false;
bool timeSyncRequested = false;
bool useTOTPAuth = false;
unsigned long lastWiFiRetryMs = 0;
unsigned long lastTimeSyncRetryMs = 0;
unsigned long timeSyncRequestMs = 0;
unsigned long lastTotpLcdRefreshMs = 0;
uint8_t lastTotpSecondsShown = 255;
int activeCardIndex = -1;
unsigned long keypadEntryStartMs = 0;
// Session-scoped TOTP anchors to survive transient WiFi loss
bool sessionTimeSynced = false;
time_t sessionScanTime = 0;
char sessionExpectedOTP[7] = "000000";

const uint8_t EVENT_LOG_SIZE = 20;
const uint8_t EVENT_MSG_LEN = 64;
char eventLog[EVENT_LOG_SIZE][EVENT_MSG_LEN];
uint8_t eventLogHead = 0;
uint8_t eventLogCount = 0;

// ==========================================
// FUNCTION PROTOTYPES, CRITICAL FOR PLATFORMIO BECAUSE IT'S A MEDICORE PRODUCT
// ==========================================
void handleIdleState();
void handleKeypadState();
void handleUnlockState();
void lcdPrint(const char* line1, const char* line2);
void updateIdleLCD();
void resetKeypadInput();
void beep(int duration);
bool syncTimeFromNTP();
void requestTimeSync();
bool waitForSystemTimeSync(unsigned long timeoutMs);
bool isSystemTimeValid();
bool isValidOnlineOTP(const char* pin);
void maintainWiFiAndTime();
void updateTotpCountdownDisplay();
void updateKeypadSessionDisplay();
void stopBuzzer();
int findWhitelistedCardIndex(const byte* uid, byte uidSize);
bool getCardTotpCodeAtTime(int cardIndex, long unixTime, char* outCode, size_t outCodeSize);
void printUidHex(const byte* uid, byte uidSize);
void logEvent(const char* message);
void startWebDashboard();
void handleWebRoot();
void handleWebStatus();
void handleWebEvents();
void handleWebAction();
const char* getStateLabel();
int getTotpSecondsRemaining();
int getKeypadSecondsRemaining();
void appendUidToString(String& out, const byte* uid, byte uidSize);
void resetRFIDSession();

// Servo rotation adjustment helper (handles base rotation offset)
int servoAdjustedAngle(int angle);
void servoWrite(int angle);

// ==========================================
// SETUP
// ==========================================

// Implementation: compute adjusted servo angle applying a base rotation offset.
// This lets us compensate when the servo is mounted rotated by 180°.
int servoAdjustedAngle(int angle) {
  const int SERVO_BASE_ROTATION_OFFSET = 180; // degrees
  int adjusted = (angle + SERVO_BASE_ROTATION_OFFSET) % 360;
  if (adjusted > 180) adjusted = 360 - adjusted;
  return adjusted;
}

void servoWrite(int angle) {
  doorServo.write(servoAdjustedAngle(angle));
}

void setup() {
  Serial.begin(115200);
  
  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  lcd.begin(16, 2);
  
  ESP32PWM::allocateTimer(0);
  doorServo.setPeriodHertz(50);
  doorServo.attach(SERVO_PIN, 500, 2400);
  servoWrite(0); 
  
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  
  // Configure PWM for passive buzzer
  ledcSetup(BUZZER_CHANNEL, BUZZER_FREQUENCY, BUZZER_RESOLUTION);
  ledcAttachPin(BUZZER_PIN, BUZZER_CHANNEL); // This might work now... flash it and pray it does
  
  lcdPrint("Connecting to", "WiFi...");
  WiFi.begin(ssid, password);
  unsigned long wifiStart = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - wifiStart < WIFI_CONNECT_TIMEOUT_MS)) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi Connected!");
    Serial.print("ESP32 IP: ");
    Serial.println(WiFi.localIP());
    logEvent("WiFi connected");
  } else {
    Serial.println("\nWiFi not connected. Continuing in offline mode."); // My literal nightmare
    logEvent("WiFi offline at boot");
  }

  // Enforce UTC Timezone 
  setenv("TZ", "UTC0", 1); // Because if we didn't, the ESP32 will shit itself and select Russia as it's timezone...
  tzset();

  if (WiFi.status() == WL_CONNECTED) {
    requestTimeSync();
    timeSynced = waitForSystemTimeSync(5000);
    timeSyncRequested = false;
    if (timeSynced) {
      Serial.println("Time synced successfully!");
      logEvent("Time synced");
    } else {
      Serial.println("Boot time sync not ready yet; staying in master mode for now.");
      logEvent("Boot time sync pending");
    }
    startWebDashboard();
  } else {
    timeSynced = false;
  }
  
  updateIdleLCD();
}

void loop() {
  webServer.handleClient();

  switch (currentState) {
    case STATE_IDLE: handleIdleState(); break;
    case STATE_KEYPAD: handleKeypadState(); break;
    case STATE_UNLOCK: handleUnlockState(); break;
  }
}

void handleIdleState() {
  maintainWiFiAndTime();

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) return;

  activeCardIndex = findWhitelistedCardIndex(mfrc522.uid.uidByte, mfrc522.uid.size);
  if (activeCardIndex < 0) {
    Serial.print("Unknown RFID UID: ");
    printUidHex(mfrc522.uid.uidByte, mfrc522.uid.size);
    logEvent("Unknown card denied");
    lcdPrint("Unknown Card", "Access Denied");
    beep(400);
    delay(1200);
    updateIdleLCD();
    resetRFIDSession();
    return;
  }

  Serial.print("Whitelisted RFID UID: ");
  printUidHex(mfrc522.uid.uidByte, mfrc522.uid.size);
  {
    char msg[EVENT_MSG_LEN];
    snprintf(msg, sizeof(msg), "Card accepted idx=%d", activeCardIndex);
    logEvent(msg);
  }

  beep(100); 
  
  if (timeSynced) {
    // Get current UTC Time
    time_t now;
    time(&now);
    
    // DEBUG: Print the Unix Timestamp
    Serial.print("Current UTC Unix Time: "); // Because either the library or the esp32 suck with syncing via internal RTC... fuck this shit
    Serial.println((long)now);
    
    // Generate full 6-digit TOTP code (explicitly cast to 32-bit long)
    if (!getCardTotpCodeAtTime(activeCardIndex, (long)now, sessionExpectedOTP, sizeof(sessionExpectedOTP))) {
      Serial.println("Failed to derive per-card TOTP. Falling back to master PIN."); // HOLY FUCKING SHIT THE WIFI IS GONE. 
      logEvent("Per-card TOTP failed, fallback PIN");
      strcpy(expectedOTP, masterPIN);
      lcdPrint("Offline Mode", "Master PIN"); // We are officially giving up on security because the WiFi died. This is utterly fucking retarded, but it's better than the project not working because the ISP is having a stroke.
      useTOTPAuth = false;
      keypadEntryStartMs = millis();
      currentState = STATE_KEYPAD;
      resetKeypadInput();
      resetRFIDSession();
      return;
    }
    // Anchor session to the scan time so losing WiFi to the Universe's cruelty doesn't break shit
    sessionTimeSynced = true;
    sessionScanTime = now;
    strncpy(expectedOTP, sessionExpectedOTP, sizeof(expectedOTP));
    
    Serial.print("Current Expected 6-Digit Code (anchored at scan): ");
    Serial.println(sessionExpectedOTP);
    logEvent("Prompting for card OTP");
    
    lcdPrint("Enter OTP:", "");
    useTOTPAuth = true;
    lastTotpSecondsShown = 255;
    updateTotpCountdownDisplay();
  } else {
    strcpy(expectedOTP, masterPIN);
    lcdPrint("Offline Mode", "Use Master PIN");
    useTOTPAuth = false;
    sessionTimeSynced = false;
    sessionScanTime = 0;
    logEvent("Prompting for master PIN");
  }
  
  keypadEntryStartMs = millis();
  currentState = STATE_KEYPAD;
  resetKeypadInput();
  resetRFIDSession(); 
}

void handleKeypadState() {
  if (millis() - keypadEntryStartMs >= OTP_ENTRY_TIMEOUT_MS) {
    lcdPrint("OTP Timeout", "Scan Card Again");
    logEvent("OTP entry timeout");
    beep(150);
    delay(1000);
    resetKeypadInput();
    activeCardIndex = -1;
    useTOTPAuth = false;
    stopBuzzer();
    resetRFIDSession();
    currentState = STATE_IDLE;
    updateIdleLCD();
    return;
  }

  if (useTOTPAuth) {
    updateTotpCountdownDisplay();
  }
  updateKeypadSessionDisplay();

  char key = keypad.getKey();
  if (key) {
    if (!isDigit(key) && key != '*' && key != '#') {
      return;
    }

    beep(50); 
    if (key == '*' || key == '#') {
      resetKeypadInput();
      if (useTOTPAuth) {
        lcdPrint("Enter OTP:", "");
        lastTotpSecondsShown = 255;
        updateTotpCountdownDisplay();
      } else {
        lcdPrint("Enter PIN:", "");
      }
      return;
    }
    enteredPIN[inputIndex] = key;
    enteredPIN[inputIndex + 1] = '\0'; 
    lcd.setCursor(inputIndex, 1);
    lcd.print('*'); 
    inputIndex++;

    // WAITS FOR 6 DIGITS
    if (inputIndex == 6) {
      bool isAuthorized = false;
      if (useTOTPAuth) {
        isAuthorized = isValidOnlineOTP(enteredPIN);
      } else {
        isAuthorized = (strcmp(enteredPIN, expectedOTP) == 0);
      }

      if (isAuthorized) {
        logEvent("PIN/OTP accepted");
        currentState = STATE_UNLOCK;
        justEnteredUnlock = true;
      } else {
        logEvent("PIN/OTP rejected");
        lcdPrint("Access Denied!", "Wrong PIN");
        beep(500); 
        delay(1500); 
        activeCardIndex = -1;
        useTOTPAuth = false;
        stopBuzzer();
        resetRFIDSession();
        currentState = STATE_IDLE;
        updateIdleLCD();
      }
    }
  }
}

void handleUnlockState() {
  if (justEnteredUnlock) {
    lcdPrint("Access Granted!", "Door Unlocked.");
    logEvent("Door unlocked");
    beep(120);
    servoWrite(-180);
    unlockStartTime = millis();
    justEnteredUnlock = false;
  }
  if (millis() - unlockStartTime >= UNLOCK_DURATION) {
    servoWrite(0);
    logEvent("Door locked");
    activeCardIndex = -1;
    useTOTPAuth = false;
    stopBuzzer();
    resetRFIDSession();
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
  else lcdPrint("Scan ID Card", "[Auth: Master]"); // Don't we use main instead of master now... eh fuck it
}

void resetKeypadInput() {
  inputIndex = 0; 
  memset(enteredPIN, 0, sizeof(enteredPIN));
}

void beep(int duration) {
  // Drive passive buzzer with PWM tone, because I totally did not forget the first time!
  ledcWrite(BUZZER_CHANNEL, 128); // 50% duty cycle
  delay(duration);
  ledcWrite(BUZZER_CHANNEL, 0); // Stop tone
}

bool syncTimeFromNTP() {
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  // SNTP runs in the background. Treat the sync as successful only once the
  // system clock has moved into a plausible Unix epoch. Otherwise shit hits the fan!
  return isSystemTimeValid();
}

void requestTimeSync() {
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
  timeSyncRequested = true;
  timeSyncRequestMs = millis();
}

bool waitForSystemTimeSync(unsigned long timeoutMs) {
  unsigned long startedMs = millis();
  while (millis() - startedMs < timeoutMs) {
    if (isSystemTimeValid()) {
      return true;
    }
    delay(100);
  }
  return isSystemTimeValid();
}

bool isSystemTimeValid() {
  time_t now;
  time(&now);
  return now > 1700000000;
}

bool isValidOnlineOTP(const char* pin) {
  if (activeCardIndex < 0) {
    Serial.println("No active card selected for OTP validation.");
    return false;
  }

  time_t now;
  time(&now);

  if (now <= 0) {
    Serial.println("Invalid system time. Rejecting OTP.");
    return false;
  }

  // Prefer using the session-anchored scan time if available so losing WiFi to german ISPs
  // during entry doesn't fuck authentication or invalidate my will to live...
  time_t baseTime = now;
  if (sessionTimeSynced && sessionScanTime > 0) {
    baseTime = sessionScanTime;
  }

  for (int8_t offset = -TOTP_ACCEPT_WINDOW_STEPS; offset <= TOTP_ACCEPT_WINDOW_STEPS; offset++) {
    long candidateTime = (long)baseTime + (offset * TOTP_STEP_SECONDS);
    char candidateCode[7];
    if (!getCardTotpCodeAtTime(activeCardIndex, candidateTime, candidateCode, sizeof(candidateCode))) {
      continue;
    }
    if (strcmp(pin, candidateCode) == 0) {
      Serial.print("OTP accepted with time-step offset: ");
      Serial.println(offset);
      logEvent("OTP valid");
      return true;
    }
  }

  Serial.println("OTP validation failed for all allowed time windows.");
  logEvent("OTP invalid");
  return false;
}

void maintainWiFiAndTime() {
  unsigned long nowMs = millis();
  static bool wasConnected = false;

  if (WiFi.status() != WL_CONNECTED) {
    wasConnected = false;
    // Mark runtime time sync as unavailable while disconnected. Keep session anchors
    // so an in-progress keypad/TOTP session can still validate against the
    // scan-anchored time. This is hacky, but it will have to work! I would not be
    // surprised if this caused a memory leak...
    if (timeSynced) {
      timeSynced = false;
      Serial.println("WiFi disconnected; marking timeSynced = false");
      logEvent("WiFi disconnected; time unsynced");
    }
    timeSyncRequested = false;

    // Do not spend foreground time trying to recover networking while a user is
    // actively interacting with RFID or the keypad. Keep the fucking thing working 
    if (currentState != STATE_IDLE) {
      return;
    }

    if (nowMs - lastWiFiRetryMs >= WIFI_RETRY_INTERVAL_MS) {
      lastWiFiRetryMs = nowMs;
      Serial.println("WiFi disconnected. Retrying...");
      logEvent("WiFi reconnect retry");
      WiFi.reconnect();
    }
    return;
  }

  if (!wasConnected) {
    wasConnected = true;
    Serial.print("WiFi connected. ESP32 IP: ");
    Serial.println(WiFi.localIP());
    logEvent("WiFi connected (runtime)");
  }

  if (!timeSynced && !timeSyncRequested && nowMs - lastTimeSyncRetryMs >= TIME_SYNC_RETRY_INTERVAL_MS) {
    lastTimeSyncRetryMs = nowMs;
    Serial.println("WiFi restored. Attempting time sync...");
    logEvent("WiFi restored, syncing time");
    if (WiFi.status() == WL_CONNECTED) {
      lcdPrint("Syncing Time...", "");
      requestTimeSync();
    }
  }

  if (!timeSynced && timeSyncRequested && isSystemTimeValid()) {
    timeSynced = true;
    timeSyncRequested = false;
    Serial.println("Time synced successfully!");
    logEvent("Time synced");
    startWebDashboard();
    updateIdleLCD();
  } else if (!timeSynced && timeSyncRequested && (nowMs - timeSyncRequestMs > TIME_SYNC_RETRY_INTERVAL_MS)) {
    timeSyncRequested = false;
    Serial.println("Time sync still pending; will retry later.");
    logEvent("Time sync pending");
  }
}

void updateTotpCountdownDisplay() {
  unsigned long nowMs = millis();
  if (nowMs - lastTotpLcdRefreshMs < TOTP_LCD_REFRESH_INTERVAL_MS) {
    return;
  }
  lastTotpLcdRefreshMs = nowMs;

  time_t now;
  time(&now);
  if (now <= 0) {
    return;
  }

  uint8_t secondsRemaining = (uint8_t)(TOTP_STEP_SECONDS - ((long)now % TOTP_STEP_SECONDS));
  if (secondsRemaining == 0 || secondsRemaining > TOTP_STEP_SECONDS) {
    secondsRemaining = (uint8_t)TOTP_STEP_SECONDS;
  }

  if (secondsRemaining == lastTotpSecondsShown) {
    return;
  }
  lastTotpSecondsShown = secondsRemaining;

  lcd.setCursor(13, 0);
  lcd.print('T');
  if (secondsRemaining < 10) {
    lcd.print('0');
  }
  lcd.print(secondsRemaining);
}

void updateKeypadSessionDisplay() {
  int secondsLeft = getKeypadSecondsRemaining();
  lcd.setCursor(13, 1);
  if (secondsLeft < 10) {
    lcd.print('0');
  } else {
    lcd.print(secondsLeft / 10);
  }
  lcd.print(secondsLeft % 10);
  lcd.print('s');
}

int findWhitelistedCardIndex(const byte* uid, byte uidSize) {
  if (uidSize != CARD_UID_LEN) {
    return -1;
  }

  for (size_t i = 0; i < WHITELIST_COUNT; i++) {
    if (memcmp(uid, whitelist[i].uid, CARD_UID_LEN) == 0) {
      return (int)i;
    }
  }

  return -1;
}

bool getCardTotpCodeAtTime(int cardIndex, long unixTime, char* outCode, size_t outCodeSize) {
  if (cardIndex < 0 || (size_t)cardIndex >= WHITELIST_COUNT || outCodeSize < 7) {
    return false;
  }

  uint8_t keyCopy[CARD_SECRET_LEN];
  memcpy(keyCopy, whitelist[cardIndex].secret, CARD_SECRET_LEN);
  TOTP cardTotp(keyCopy, CARD_SECRET_LEN);
  char* code = cardTotp.getCode(unixTime);
  if (code == nullptr) {
    return false;
  }

  strncpy(outCode, code, outCodeSize - 1);
  outCode[outCodeSize - 1] = '\0';
  return true;
}

void printUidHex(const byte* uid, byte uidSize) {
  for (byte i = 0; i < uidSize; i++) {
    if (uid[i] < 0x10) {
      Serial.print('0');
    }
    Serial.print(uid[i], HEX);
    if (i + 1 < uidSize) {
      Serial.print(':');
    }
  }
  Serial.println();
}

void logEvent(const char* message) {
  strncpy(eventLog[eventLogHead], message, EVENT_MSG_LEN - 1);
  eventLog[eventLogHead][EVENT_MSG_LEN - 1] = '\0';
  eventLogHead = (eventLogHead + 1) % EVENT_LOG_SIZE;
  if (eventLogCount < EVENT_LOG_SIZE) {
    eventLogCount++;
  }
}

const char* getStateLabel() {
  switch (currentState) {
    case STATE_IDLE: return "IDLE";
    case STATE_KEYPAD: return "KEYPAD";
    case STATE_UNLOCK: return "UNLOCK";
    default: return "UNKNOWN";
  }
}

int getTotpSecondsRemaining() {
  time_t now;
  time(&now);
  if (now <= 0) {
    return -1;
  }
  int remaining = (int)(TOTP_STEP_SECONDS - ((long)now % TOTP_STEP_SECONDS));
  if (remaining <= 0 || remaining > TOTP_STEP_SECONDS) {
    remaining = (int)TOTP_STEP_SECONDS;
  }
  return remaining;
}

int getKeypadSecondsRemaining() {
  if (currentState != STATE_KEYPAD) {
    return 0;
  }
  unsigned long elapsed = millis() - keypadEntryStartMs;
  if (elapsed >= OTP_ENTRY_TIMEOUT_MS) {
    return 0;
  }
  return (int)((OTP_ENTRY_TIMEOUT_MS - elapsed + 999) / 1000);
}

void startWebDashboard() {
  static bool started = false;
  if (started) {
    return;
  }

  webServer.on("/", handleWebRoot);
  webServer.on("/api/status", handleWebStatus);
  webServer.on("/api/events", handleWebEvents);
  webServer.on("/action", handleWebAction);
  webServer.begin();
  started = true;
  logEvent("Web dashboard started");
}

void handleWebRoot() {
  String html;
  html.reserve(1800); // Clear that motherfucker out. If I don't reserve this memory upfront, 
                      // the heap fragments into a million pieces and the ESP32 shits itself 
                      // after three page refreshes.
  html += "<!doctype html><html><head><meta charset='utf-8'>";
  html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>DoorControl Dashboard</title>";
  html += "<style>body{font-family:Verdana,sans-serif;background:#f2f4f8;margin:0;padding:20px;}";
  html += "h1{margin:0 0 12px;} .card{background:#fff;border-radius:10px;padding:14px;margin:10px 0;box-shadow:0 2px 8px rgba(0,0,0,.08);} button{padding:10px 12px;margin:4px;} pre{white-space:pre-wrap;}";
  html += "</style></head><body>";
  html += "<h1>DoorControl</h1>";
  html += "<div class='card'><b>State:</b> ";
  html += getStateLabel();
  html += "<br><b>WiFi:</b> ";
  html += (WiFi.status() == WL_CONNECTED ? "Connected" : "Disconnected");
  html += "<br><b>Time Synced:</b> ";
  html += (timeSynced ? "Yes" : "No");
  html += "<br><b>Auth Mode:</b> ";
  html += (useTOTPAuth ? "Card TOTP" : "Master PIN");
  html += "<br><b>Active Card Index:</b> ";
  html += String(activeCardIndex);
  html += "<br><b>TOTP Sec Left:</b> ";
  html += String(getTotpSecondsRemaining());
  html += "<br><b>Keypad Sec Left:</b> ";
  html += String(getKeypadSecondsRemaining());
  html += "</div>";
  html += "<div class='card'><a href='/action?cmd=buzzer'><button>Buzzer Test</button></a>";
  html += "<a href='/action?cmd=unlock'><button>Unlock Test</button></a>";
  html += "<a href='/action?cmd=resync'><button>Time Resync</button></a></div>";
  html += "<div class='card'><b>Whitelisted UIDs</b><pre>";
  for (size_t i = 0; i < WHITELIST_COUNT; i++) {
    html += "#";
    html += String((int)i);
    html += " ";
    appendUidToString(html, whitelist[i].uid, CARD_UID_LEN);
    html += "\n";
  }
  html += "</pre></div>";
  html += "<div class='card'><b>Recent Events</b><pre>";
  for (int i = 0; i < eventLogCount; i++) {
    int idx = (eventLogHead + EVENT_LOG_SIZE - eventLogCount + i) % EVENT_LOG_SIZE;
    html += eventLog[idx];
    html += "\n";
  }
  html += "</pre></div>";
  html += "<script>setTimeout(()=>location.reload(),";
  html += String(WEB_STATUS_REFRESH_MS);
  html += ");</script></body></html>";

  webServer.send(200, "text/html", html);
}

void handleWebStatus() {
  String json = "{";
  json += "\"state\":\"" + String(getStateLabel()) + "\",";
  json += "\"wifi\":" + String(WiFi.status() == WL_CONNECTED ? "true" : "false") + ",";
  json += "\"timeSynced\":" + String(timeSynced ? "true" : "false") + ",";
  json += "\"authMode\":\"" + String(useTOTPAuth ? "totp" : "master") + "\",";
  json += "\"activeCardIndex\":" + String(activeCardIndex) + ",";
  json += "\"totpSecLeft\":" + String(getTotpSecondsRemaining()) + ",";
  json += "\"keypadSecLeft\":" + String(getKeypadSecondsRemaining()) + ",";
  json += "\"whitelistCount\":" + String((int)WHITELIST_COUNT);
  json += "}";
  webServer.send(200, "application/json", json);
}

void handleWebEvents() {
  String body;
  for (int i = 0; i < eventLogCount; i++) {
    int idx = (eventLogHead + EVENT_LOG_SIZE - eventLogCount + i) % EVENT_LOG_SIZE;
    body += eventLog[idx];
    body += "\n";
  }
  webServer.send(200, "text/plain", body);
}

void handleWebAction() {
  String cmd = webServer.arg("cmd");
  if (cmd == "buzzer") {
    beep(150);
    logEvent("Web action: buzzer");
  } else if (cmd == "unlock") {
    servoWrite(0);
    delay(500);
    servoWrite(90);
    logEvent("Web action: unlock test");
  } else if (cmd == "resync") {
    if (WiFi.status() == WL_CONNECTED) {
      requestTimeSync();
      timeSynced = waitForSystemTimeSync(5000);
      timeSyncRequested = false;
      updateIdleLCD();
      if (timeSynced) {
        logEvent("Web action: time resync");
      } else {
        logEvent("Web action: time resync pending");
      }
    }
  }

  webServer.sendHeader("Location", "/");
  webServer.send(303);
}

void resetRFIDSession() {
  stopBuzzer();
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

void stopBuzzer() {
  // Ensure PWM is stopped and pin is low, otherwise it sounds like
  // the heartbeat to my will to live... 
  ledcWrite(BUZZER_CHANNEL, 0);
  digitalWrite(BUZZER_PIN, LOW);
}

void appendUidToString(String& out, const byte* uid, byte uidSize) {
  for (byte i = 0; i < uidSize; i++) {
    if (uid[i] < 0x10) {
      out += '0';
    }
    out += String(uid[i], HEX);
    if (i + 1 < uidSize) {
      out += ':';
    }
  }
}
