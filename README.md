# DoorControlSys

A school Proof-of-Concept (PoC) for a multi-factor door access control system running on an **ESP32**. The system combines RFID card scanning, TOTP (Time-based One-Time Password) authentication, and a 4×4 keypad, with a servo-actuated door lock and a live web dashboard for monitoring.

---

## Table of Contents

- [Overview](#overview)
- [Hardware Components](#hardware-components)
- [Wiring / Pinout](#wiring--pinout)
- [Libraries & Build System](#libraries--build-system)
- [How It Works](#how-it-works)
  - [Authentication Flow](#authentication-flow)
  - [Online Mode (TOTP)](#online-mode-totp)
  - [Offline Mode (Master PIN)](#offline-mode-master-pin)
  - [Door Unlock](#door-unlock)
- [Web Dashboard](#web-dashboard)
- [State Machine](#state-machine)
- [WiFi & NTP Time Sync](#wifi--ntp-time-sync)
- [Event Logging](#event-logging)
- [Security Notes](#security-notes)
- [Known Limitations](#known-limitations)

---

## Overview

DoorControlSys is a two-factor access control system:

1. **Factor 1 – RFID**: The user taps a registered MIFARE card against the MFRC522 reader. The card's UID is checked against an in-firmware whitelist.
2. **Factor 2 – PIN/OTP**: After a successful card scan, the user enters a 6-digit code on the keypad. When the ESP32 has an internet connection and a valid NTP time sync, this code is a **per-card TOTP** (unique secret per card, compatible with apps like Google Authenticator). When offline, a shared **master PIN** is accepted as a fallback.

A servo motor physically actuates the door latch. A 16×2 LCD and a passive buzzer provide real-time user feedback. A built-in HTTP web server serves a live status dashboard and a simple event log.

---

## Hardware Components

| Component | Purpose |
|---|---|
| **ESP32 DOIT DevKit V1** | Main microcontroller (240 MHz, 320 KB RAM, 4 MB Flash) |
| **MFRC522 RFID Reader** | Reads 13.56 MHz MIFARE card UIDs via SPI |
| **4×4 Matrix Keypad** | 6-digit PIN / OTP entry |
| **16×2 LCD Display** | Status messages and countdown timers |
| **Servo Motor** | Actuates the physical door latch |
| **Passive Buzzer** | Audible feedback (beeps on key press, accept, deny) |

---

## Wiring / Pinout

A full pinout spreadsheet is included as **`Pinout.xlsx`**. The key assignments coded in firmware are:

| Signal | GPIO |
|---|---|
| RFID SS (SPI CS) | 5 |
| RFID RST | Hardwired to 3.3 V (not toggled by firmware) |
| LCD RS | 22 |
| LCD EN | 21 |
| LCD D4–D7 | 17, 16, 2, 15 |
| Keypad ROW 1–4 | 13, 12, 14, 27 |
| Keypad COL 1–4 | 26, 25, 4, 0 |
| Servo | 32 |
| Buzzer | 33 |

> **⚠️ GPIO 0 warning:** GPIO 0 is used as keypad column 4. Holding it LOW while powering on forces the ESP32 into bootloader mode. Do not press a key on that column while plugging in power.

---

## Libraries & Build System

The project is built with **PlatformIO** targeting the `esp32dev` board (Arduino framework).

| Library | Version | Role |
|---|---|---|
| MFRC522 | 1.4.12 | RFID reader driver |
| LiquidCrystal | 1.5.0 | 16×2 LCD driver |
| Keypad | 3.1.1 | Matrix keypad scanning |
| ESP32Servo | 3.2.0 | Servo PWM control |
| TOTP library | 1.1.0 | RFC 6238 TOTP code generation (SHA-1) |
| SPI | 2.0.0 | SPI bus (RFID) |
| WiFi | 2.0.0 | WiFi connectivity & WebServer |

To build and flash:

```bash
pio run --target upload
```

---

## How It Works

### Authentication Flow

```
User taps RFID card
        │
        ▼
  UID in whitelist?
   No ──► "Access Denied" (long beep)
   Yes ──► Short beep
        │
        ▼
  WiFi connected & time synced?
   Yes ──► Generate per-card TOTP, prompt "Enter OTP:"
   No  ──► Fallback, prompt "Offline Mode / Enter Master PIN"
        │
        ▼
  User enters 6 digits on keypad (60-second timeout)
        │
        ▼
  Code matches?
   No  ──► "Access Denied / Wrong PIN" (long beep), return to idle
   Yes ──► "Access Granted! Door Unlocked." (short beep)
        │
        ▼
  Servo rotates to 90° (unlocked) for 5 seconds
  Servo returns to 0° (locked), return to idle
```

### Online Mode (TOTP)

When the ESP32 is connected to WiFi and has synchronized its clock via NTP (`pool.ntp.org`, UTC), it generates a **card-specific TOTP code**:

- Each whitelisted card has a unique 10-byte HMAC-SHA1 secret stored in firmware.
- The 6-digit code is derived using the standard RFC 6238 algorithm with a 30-second step.
- To tolerate minor clock drift, the system accepts codes from the current step as well as ±1 step (±30 seconds).
- The TOTP code is **anchored at the moment the card is scanned**, so a brief WiFi dropout during PIN entry will not invalidate the session.
- The LCD displays a live countdown showing seconds remaining in the current TOTP window (`T##` in the top-right corner).

Users can pair their card with any TOTP authenticator app (Google Authenticator, Authy, etc.) using the corresponding base32-encoded secret.

### Offline Mode (Master PIN)

If WiFi is unavailable or the NTP time sync has not yet completed, the system falls back to a single shared 6-digit master PIN. This allows the door to be operated even without network connectivity, at the cost of reduced security (no per-user or time-scoped codes).

### Door Unlock

On successful authentication:

1. The LCD shows `"Access Granted! / Door Unlocked."`
2. The buzzer emits a short beep.
3. The servo rotates to **90°** (unlocked position).
4. After **5 seconds**, the servo returns to **0°** (locked) and the system returns to idle.

---

## Web Dashboard

When the ESP32 connects to WiFi it starts an HTTP server on **port 80**. Navigate to the device's IP address in a browser to access the dashboard.

The dashboard auto-refreshes every 2 seconds and displays:

- Current system state (IDLE / KEYPAD / UNLOCK)
- WiFi connection status
- NTP time-sync status
- Active authentication mode (Card TOTP or Master PIN)
- Active card index and TOTP/keypad countdown timers
- Full whitelist of registered card UIDs
- Rolling log of the last 20 system events

The dashboard also provides three control buttons:

| Button | Action |
|---|---|
| **Buzzer Test** | Triggers a short test beep |
| **Unlock Test** | Briefly actuates the servo (0° → 90° → 0°) |
| **Time Resync** | Forces an immediate NTP resync |

A JSON status endpoint is available at `/api/status` and a plain-text event log at `/api/events`.

---

## State Machine

The firmware runs a simple three-state machine in the main loop:

| State | Description |
|---|---|
| `STATE_IDLE` | Waiting for an RFID card. Continuously maintains WiFi/NTP and serves web requests. |
| `STATE_KEYPAD` | Card accepted; waiting for the user to enter a 6-digit code. Times out after 60 seconds. |
| `STATE_UNLOCK` | Code accepted; door is physically unlocked for 5 seconds before auto-locking. |

---

## WiFi & NTP Time Sync

- The ESP32 attempts to connect to the configured WiFi network at boot with a **15-second timeout**.
- If WiFi is unavailable at boot, the system enters offline/master-PIN mode immediately.
- In `STATE_IDLE`, WiFi is periodically retried every **30 seconds**.
- Once WiFi is restored, NTP sync is reattempted every **60 seconds** until successful.
- Time is always kept in **UTC** to ensure correct TOTP calculation regardless of locale.

---

## Event Logging

The firmware maintains a ring buffer of the last **20 events** in RAM (not persistent across reboots). Events are viewable on the web dashboard and include:

- WiFi connect/disconnect
- NTP time sync success/failure
- Card accepted/denied (with index)
- OTP accepted/rejected
- Door locked/unlocked
- Web dashboard actions

---

## Security Notes

> This is a **school PoC**. The following known security trade-offs were made intentionally for simplicity and should **not** be used in a production environment.

- Card UIDs and TOTP secrets are hardcoded in firmware as a plaintext whitelist.
- The master PIN (`123456`) and WiFi credentials are hardcoded in source.
- TOTP secrets are stored in flash unencrypted.
- The web dashboard has no authentication; anyone on the same network can trigger the buzzer or unlock the door.
- The RFID card UID alone is not a secret — UIDs can be cloned. TOTP provides the actual second factor.

---

## Known Limitations

- Whitelist changes require a firmware recompile and reflash.
- Web dashboard is HTTP only (no TLS).
- No persistent event log; events are lost on reboot.
- GPIO 0 as keypad column creates a boot-mode conflict if pressed during power-on.
- The MFRC522 RST pin is hardwired to 3.3 V; the library is passed pin `255` as a workaround to prevent it from toggling a non-existent pin.
