#include "AmoledUx.h"

#include <Wire.h>
#include <string.h>

#include "BoardProfile.h"
#include "Diagnostics.h"

namespace {
constexpr uint16_t LCD_WIDTH = BoardProfile::kDisplayWidth;
constexpr uint16_t LCD_HEIGHT = BoardProfile::kDisplayHeight;
constexpr uint8_t LCD_ROTATION = BoardProfile::kDisplayRotation;
constexpr bool SMALL_UI = BoardProfile::kSmallDisplay;

constexpr uint16_t COLOR_BG = 0x0000;
constexpr uint16_t COLOR_PANEL = 0x1082;
constexpr uint16_t COLOR_PANEL_2 = 0x2104;
constexpr uint16_t COLOR_TEXT = 0xFFFF;
constexpr uint16_t COLOR_DIM = 0xBDF7;
constexpr uint16_t COLOR_ACCENT = 0x07FF;
constexpr uint16_t COLOR_GOOD = 0x07E0;
constexpr uint16_t COLOR_WARN = 0xFD20;
constexpr uint16_t COLOR_BAD = 0xF800;

constexpr int16_t PAD = SMALL_UI ? 8 : 22;
constexpr int16_t HEADER_H = SMALL_UI ? 28 : 58;
constexpr int16_t FOOTER_H = SMALL_UI ? 22 : 42;
constexpr int16_t BODY_TOP = SMALL_UI ? 42 : 82;
constexpr uint8_t TITLE_TEXT = SMALL_UI ? 2 : 3;
constexpr uint8_t BODY_TEXT = SMALL_UI ? 1 : 2;
constexpr uint8_t HEADER_TEXT = SMALL_UI ? 1 : 2;
constexpr size_t LINE_CHARS = SMALL_UI ? 20 : 30;

void copyClipped(char *out, size_t outLen, const char *in, size_t maxChars) {
  if (!outLen) return;
  if (!in) in = "";
  size_t len = strnlen(in, maxChars + 1);
  bool clipped = len > maxChars;
  if (clipped) len = maxChars;
  size_t writeLen = min(len, outLen - 1);
  memcpy(out, in, writeLen);
  out[writeLen] = '\0';
  if (clipped && outLen >= 4 && writeLen >= 3) {
    out[writeLen - 3] = '.';
    out[writeLen - 2] = '.';
    out[writeLen - 1] = '.';
  }
}
}  // namespace

#if defined(ESP32_KEY_BOARD_TOUCH_LCD147)
void Esp32KeyST7789::applyMadctlFix(uint8_t rotation, bool mirrorX, bool mirrorY) {
  uint8_t madctl = 0;
  switch (rotation % 4) {
    case 0:
      madctl = ST77XX_MADCTL_MX | ST77XX_MADCTL_MY | ST77XX_MADCTL_RGB;
      break;
    case 1:
      madctl = ST77XX_MADCTL_MY | ST77XX_MADCTL_MV | ST77XX_MADCTL_RGB;
      break;
    case 2:
      madctl = ST77XX_MADCTL_RGB;
      break;
    case 3:
      madctl = ST77XX_MADCTL_MX | ST77XX_MADCTL_MV | ST77XX_MADCTL_RGB;
      break;
  }

  if (mirrorX) {
    madctl ^= ST77XX_MADCTL_MX;
  }
  if (mirrorY) {
    madctl ^= ST77XX_MADCTL_MY;
  }

  sendCommand(ST77XX_MADCTL, &madctl, 1);
}
#endif

void AmoledUx::begin() {
  if (!initDisplay() || !beginDisplay()) {
    Diagnostics::log("UX: display init failed");
    ready_ = false;
    return;
  }

  setDisplayRotation(LCD_ROTATION);
#if defined(ESP32_KEY_BOARD_AMOLED18)
  amoled_->setBrightness(BoardProfile::kAmoledBrightness);
#endif
  setDisplayTextWrap(false);
  displayFillScreen(COLOR_BG);
  ready_ = true;
  idle();
  Diagnostics::logf("UX: display ready: %s", BoardProfile::kBoardName);
}

void AmoledUx::idle() {
  Diagnostics::log("UX: idle");
  if (!ready_) return;

  returnToReadyAt_ = 0;
  drawBase("ESP32 FIDO", COLOR_ACCENT, "Lab build only");
  printText(PAD, BODY_TOP, "Authenticator", TITLE_TEXT, COLOR_TEXT, COLOR_BG);
  printText(PAD, BODY_TOP + (SMALL_UI ? 34 : 54), "Waiting for USB host", BODY_TEXT, COLOR_DIM,
            COLOR_BG);
  printText(PAD, BODY_TOP + (SMALL_UI ? 58 : 104), "No secrets on screen", BODY_TEXT, COLOR_DIM,
            COLOR_BG);
  printText(PAD, BODY_TOP + (SMALL_UI ? 82 : 158), "Use test accounts only", BODY_TEXT,
            COLOR_WARN, COLOR_BG);
}

void AmoledUx::usbReady() {
  Diagnostics::log("UX: USB FIDO HID ready");
  if (!ready_) return;

  returnToReadyAt_ = 0;
  drawBase("ESP32 FIDO", COLOR_GOOD, "BOOT confirms actions");
  printText(PAD, BODY_TOP, "USB HID ready", TITLE_TEXT, COLOR_GOOD, COLOR_BG);
  printText(PAD, BODY_TOP + (SMALL_UI ? 34 : 58), "Waiting for WebAuthn", BODY_TEXT, COLOR_TEXT,
            COLOR_BG);
  if (!hasTrace_) {
    printText(PAD, BODY_TOP + (SMALL_UI ? 58 : 108), "Register/sign-in prompts", BODY_TEXT,
              COLOR_DIM, COLOR_BG);
    printText(PAD, BODY_TOP + (SMALL_UI ? 76 : 136), "will appear here.", BODY_TEXT, COLOR_DIM,
              COLOR_BG);
    if (hasRecorderStatus_) {
      printClipped(PAD, BODY_TOP + (SMALL_UI ? 112 : 190), recorderStatus_, LINE_CHARS, BODY_TEXT,
                   COLOR_DIM, COLOR_BG);
      printClipped(PAD, BODY_TOP + (SMALL_UI ? 130 : 220), recorderLast_, LINE_CHARS, BODY_TEXT,
                   COLOR_DIM, COLOR_BG);
    }
    return;
  }
  // Surface the last request outcome as a passive trace so the operator can
  // tell real RP activity apart from synthetic/fallback host probes.
  char line[48];
  snprintf(line, sizeof(line), "Last: %s", traceCommand_);
  printClipped(PAD, BODY_TOP + (SMALL_UI ? 58 : 104), line, LINE_CHARS, BODY_TEXT, COLOR_DIM,
               COLOR_BG);
  snprintf(line, sizeof(line), "%s %s", traceSynthetic_ ? "synthetic" : "RP", traceRp_);
  printClipped(PAD, BODY_TOP + (SMALL_UI ? 76 : 134), line, LINE_CHARS, BODY_TEXT,
               traceSynthetic_ ? COLOR_WARN : COLOR_TEXT, COLOR_BG);
  snprintf(line, sizeof(line), "Status: %s", traceStatus_);
  printClipped(PAD, BODY_TOP + (SMALL_UI ? 94 : 164), line, LINE_CHARS, BODY_TEXT, COLOR_DIM,
               COLOR_BG);
  if (hasRecorderStatus_) {
    printClipped(PAD, BODY_TOP + (SMALL_UI ? 124 : 212), recorderStatus_, LINE_CHARS, BODY_TEXT,
                 COLOR_DIM, COLOR_BG);
    printClipped(PAD, BODY_TOP + (SMALL_UI ? 142 : 242), recorderLast_, LINE_CHARS, BODY_TEXT,
                 COLOR_DIM, COLOR_BG);
  }
}

void AmoledUx::diagnostic(const char *title, const char *line1, const char *line2) {
  Diagnostics::logf("UX: diag: %s %s %s", title ? title : "", line1 ? line1 : "",
                    line2 ? line2 : "");
  if (!ready_) return;

  drawBase(title ? title : "Diagnostic", COLOR_ACCENT, "Browser trace");
  printClipped(PAD, BODY_TOP, line1 ? line1 : "", LINE_CHARS, BODY_TEXT, COLOR_TEXT, COLOR_BG);
  if (line2 && line2[0]) {
    printClipped(PAD, BODY_TOP + (SMALL_UI ? 24 : 40), line2, LINE_CHARS, BODY_TEXT, COLOR_DIM,
                 COLOR_BG);
  }
  returnToReadyAt_ = millis() + 1800;
}

void AmoledUx::diagnosticError(const char *title, const char *line1, const char *line2) {
  Diagnostics::logf("UX: diag error: %s %s %s", title ? title : "", line1 ? line1 : "",
                    line2 ? line2 : "");
  if (!ready_) return;

  drawBase(title ? title : "Rejected", COLOR_BAD, "Check settings");
  printClipped(PAD, BODY_TOP, line1 ? line1 : "", LINE_CHARS, BODY_TEXT, COLOR_BAD, COLOR_BG);
  if (line2 && line2[0]) {
    printClipped(PAD, BODY_TOP + (SMALL_UI ? 24 : 40), line2, LINE_CHARS, BODY_TEXT, COLOR_TEXT,
                 COLOR_BG);
  }
  returnToReadyAt_ = millis() + 5000;
}

void AmoledUx::waitingForPresence(const char *action, const char *rpId) {
  Diagnostics::logf("UX: %s %s - press BOOT", action, rpId ? rpId : "");
  if (!ready_) return;

  returnToReadyAt_ = 0;
  char actionLine[32];
  char rpLine[40];
  copyClipped(actionLine, sizeof(actionLine), action ? action : "Confirm", 20);
  copyClipped(rpLine, sizeof(rpLine), rpId && rpId[0] ? rpId : "unknown relying party",
              SMALL_UI ? 21 : 31);

  drawBase("User Presence", COLOR_WARN, "Press BOOT to approve");
  printText(PAD, BODY_TOP, actionLine, TITLE_TEXT, COLOR_WARN, COLOR_BG);
  printText(PAD, BODY_TOP + (SMALL_UI ? 36 : 62), "Relying party", BODY_TEXT, COLOR_DIM,
            COLOR_BG);
  printClipped(PAD, BODY_TOP + (SMALL_UI ? 54 : 94), rpLine, LINE_CHARS, BODY_TEXT, COLOR_TEXT,
               COLOR_BG);
  printText(PAD, BODY_TOP + (SMALL_UI ? 90 : 156), "Only approve requests", BODY_TEXT,
            COLOR_TEXT, COLOR_BG);
  printText(PAD, BODY_TOP + (SMALL_UI ? 108 : 184), "you started.", BODY_TEXT, COLOR_TEXT,
            COLOR_BG);
}

void AmoledUx::adminStatus(size_t totalCredentials, size_t residentCredentials, size_t remainingSlots,
                           bool awaitingConfirm) {
  Diagnostics::logf("UX: admin: total=%u resident=%u remaining=%u confirm=%u",
                    static_cast<unsigned>(totalCredentials), static_cast<unsigned>(residentCredentials),
                    static_cast<unsigned>(remainingSlots), awaitingConfirm ? 1 : 0);
  if (!ready_) return;

  returnToReadyAt_ = 0;
  const bool full = remainingSlots == 0;
  drawBase(awaitingConfirm ? "Admin Reset" : "Admin", awaitingConfirm ? COLOR_BAD : COLOR_ACCENT,
           awaitingConfirm ? "Hold BOOT 5s to wipe" : "Release BOOT to exit");

  char line[40];
  snprintf(line, sizeof(line), "Credentials: %u/%u", static_cast<unsigned>(totalCredentials),
           static_cast<unsigned>(totalCredentials + remainingSlots));
  printText(PAD, BODY_TOP, line, BODY_TEXT, full ? COLOR_WARN : COLOR_TEXT, COLOR_BG);

  snprintf(line, sizeof(line), "Discoverable: %u", static_cast<unsigned>(residentCredentials));
  printText(PAD, BODY_TOP + (SMALL_UI ? 20 : 38), line, BODY_TEXT, COLOR_DIM, COLOR_BG);

  snprintf(line, sizeof(line), "Free slots: %u", static_cast<unsigned>(remainingSlots));
  printText(PAD, BODY_TOP + (SMALL_UI ? 40 : 76), line, BODY_TEXT, full ? COLOR_BAD : COLOR_GOOD,
            COLOR_BG);

  if (full) {
    printText(PAD, BODY_TOP + (SMALL_UI ? 66 : 122), "Storage full", TITLE_TEXT, COLOR_WARN,
              COLOR_BG);
  }

  if (awaitingConfirm) {
    printText(PAD, BODY_TOP + (SMALL_UI ? 106 : 176), "This wipes credentials", BODY_TEXT,
              COLOR_TEXT, COLOR_BG);
    printText(PAD, BODY_TOP + (SMALL_UI ? 124 : 204), "and the lab PIN.", BODY_TEXT, COLOR_TEXT,
              COLOR_BG);
  } else {
    printText(PAD, BODY_TOP + (SMALL_UI ? 106 : 176), "Hold BOOT again to", BODY_TEXT,
              COLOR_TEXT, COLOR_BG);
    printText(PAD, BODY_TOP + (SMALL_UI ? 124 : 204), "open wipe confirm.", BODY_TEXT, COLOR_TEXT,
              COLOR_BG);
  }
  if (hasRecorderStatus_) {
    printClipped(PAD, BODY_TOP + (SMALL_UI ? 156 : 252), recorderStatus_, LINE_CHARS, BODY_TEXT,
                 COLOR_DIM, COLOR_BG);
  }
}

void AmoledUx::success(const char *message) {
  Diagnostics::logf("UX: success: %s", message);
  drawStatus("Success", message, COLOR_GOOD);
  returnToReadyAt_ = millis() + 2500;
}

void AmoledUx::error(const char *message) {
  Diagnostics::logf("UX: error: %s", message);
  drawStatus("Error", message, COLOR_BAD);
  returnToReadyAt_ = millis() + 5000;
}

void AmoledUx::trace(const char *command, const char *rpId, const char *status, bool synthetic) {
  Diagnostics::logf("UX: trace: cmd=%s rp=%s status=%s %s", command ? command : "", rpId ? rpId : "",
                    status ? status : "", synthetic ? "synthetic" : "real");
  copyClipped(traceCommand_, sizeof(traceCommand_), command ? command : "-", sizeof(traceCommand_) - 1);
  copyClipped(traceRp_, sizeof(traceRp_), rpId && rpId[0] ? rpId : "-", sizeof(traceRp_) - 1);
  copyClipped(traceStatus_, sizeof(traceStatus_), status ? status : "-", sizeof(traceStatus_) - 1);
  traceSynthetic_ = synthetic;
  hasTrace_ = true;
  // Intentionally no drawBase/returnToReadyAt_ here: a synthetic or up=false
  // probe must not repaint the screen or interrupt an active real-RP prompt.
}

void AmoledUx::recorderStatus(const char *status, const char *lastEvent) {
  copyClipped(recorderStatus_, sizeof(recorderStatus_), status ? status : "-", 34);
  copyClipped(recorderLast_, sizeof(recorderLast_), lastEvent ? lastEvent : "-", 46);
  hasRecorderStatus_ = true;
}

void AmoledUx::poll() {
  if (!ready_ || returnToReadyAt_ == 0) return;
  if (static_cast<int32_t>(millis() - returnToReadyAt_) >= 0) {
    usbReady();
  }
}

void AmoledUx::drawBase(const char *title, uint16_t accentColor, const char *footer) {
  if (!ready_) return;

  displayFillScreen(COLOR_BG);
  displayFillRect(0, 0, LCD_WIDTH, HEADER_H, COLOR_PANEL);
  displayFillRect(0, HEADER_H - (SMALL_UI ? 3 : 4), LCD_WIDTH, SMALL_UI ? 3 : 4,
                  accentColor);
  printText(PAD, SMALL_UI ? 8 : 18, title, HEADER_TEXT, COLOR_TEXT, COLOR_PANEL);

  displayFillRect(0, LCD_HEIGHT - FOOTER_H, LCD_WIDTH, FOOTER_H, COLOR_PANEL_2);
  printClipped(PAD, LCD_HEIGHT - (SMALL_UI ? 15 : 29), footer, LINE_CHARS, BODY_TEXT, COLOR_DIM,
               COLOR_PANEL_2);
}

void AmoledUx::drawStatus(const char *label, const char *message, uint16_t color) {
  if (!ready_) return;

  drawBase(label, color, "Ready for next request");
  printText(PAD, BODY_TOP, label, TITLE_TEXT, color, COLOR_BG);
  printClipped(PAD, BODY_TOP + (SMALL_UI ? 40 : 66), message ? message : "", LINE_CHARS,
               BODY_TEXT, COLOR_TEXT, COLOR_BG);
}

void AmoledUx::printText(int16_t x, int16_t y, const char *text, uint8_t size, uint16_t color,
                         uint16_t bg) {
  if (!ready_) return;
  displaySetTextSize(size);
  displaySetTextColor(color, bg);
  displaySetCursor(x, y);
  displayPrint(text ? text : "");
}

void AmoledUx::printClipped(int16_t x, int16_t y, const char *text, size_t maxChars,
                            uint8_t size, uint16_t color, uint16_t bg) {
  char line[48];
  copyClipped(line, sizeof(line), text, maxChars);
  printText(x, y, line, size, color, bg);
}

bool AmoledUx::initDisplay() {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  initAmoledPowerExpander();
  bus_ = new Arduino_ESP32QSPI(BoardProfile::kDisplayCs, BoardProfile::kDisplaySclk,
                               BoardProfile::kAmoledSdio0, BoardProfile::kAmoledSdio1,
                               BoardProfile::kAmoledSdio2, BoardProfile::kAmoledSdio3);
  amoled_ = new Arduino_SH8601(bus_, BoardProfile::kDisplayRst, LCD_ROTATION, LCD_WIDTH,
                               LCD_HEIGHT);
  display_ = amoled_;
  return display_ != nullptr;
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  pinMode(BoardProfile::kDisplayBacklight, OUTPUT);
  digitalWrite(BoardProfile::kDisplayBacklight, HIGH);
  SPI.begin(BoardProfile::kDisplaySclk, -1, BoardProfile::kDisplayMosi,
            BoardProfile::kDisplayCs);
  lcd_ = new Esp32KeyST7789(&SPI, BoardProfile::kDisplayCs, BoardProfile::kDisplayDc,
                            BoardProfile::kDisplayRst);
  return lcd_ != nullptr;
#else
  return false;
#endif
}

bool AmoledUx::beginDisplay() {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  return display_ && display_->begin();
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (!lcd_) return false;
  lcd_->init(LCD_WIDTH, LCD_HEIGHT, SPI_MODE0);
  lcd_->setColRowStart(BoardProfile::kDisplayColOffset, BoardProfile::kDisplayRowOffset);
  return true;
#else
  return false;
#endif
}

void AmoledUx::setDisplayRotation(uint8_t rotation) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->setRotation(rotation);
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) {
    lcd_->setRotation(rotation);
    lcd_->applyMadctlFix(rotation, true, false);
  }
#endif
}

void AmoledUx::setDisplayTextWrap(bool wrap) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->setTextWrap(wrap);
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) lcd_->setTextWrap(wrap);
#endif
}

void AmoledUx::displayFillScreen(uint16_t color) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->fillScreen(color);
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) lcd_->fillScreen(color);
#endif
}

void AmoledUx::displayFillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->fillRect(x, y, w, h, color);
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) lcd_->fillRect(x, y, w, h, color);
#endif
}

void AmoledUx::displaySetTextSize(uint8_t size) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->setTextSize(size);
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) lcd_->setTextSize(size);
#endif
}

void AmoledUx::displaySetTextColor(uint16_t color, uint16_t bg) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->setTextColor(color, bg);
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) lcd_->setTextColor(color, bg);
#endif
}

void AmoledUx::displaySetCursor(int16_t x, int16_t y) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->setCursor(x, y);
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) lcd_->setCursor(x, y);
#endif
}

void AmoledUx::displayPrint(const char *text) {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  if (display_) display_->print(text ? text : "");
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  if (lcd_) lcd_->print(text ? text : "");
#endif
}

void AmoledUx::initAmoledPowerExpander() {
#if defined(ESP32_KEY_BOARD_AMOLED18)
  Wire.begin(BoardProfile::kI2cSda, BoardProfile::kI2cScl);
  if (!expander_.begin(BoardProfile::kAmoledExpanderAddr, &Wire)) {
    Diagnostics::log("UX: XCA9554 not found; trying AMOLED init");
    return;
  }

  for (uint8_t pin = 0; pin < 3; pin++) {
    expander_.pinMode(pin, OUTPUT);
    expander_.digitalWrite(pin, LOW);
  }
  expander_.pinMode(7, OUTPUT);
  expander_.digitalWrite(7, HIGH);
  delay(20);
  for (uint8_t pin = 0; pin < 3; pin++) {
    expander_.digitalWrite(pin, HIGH);
  }
#endif
}
