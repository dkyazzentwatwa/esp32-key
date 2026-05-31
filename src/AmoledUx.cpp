#include "AmoledUx.h"

#include <Wire.h>
#include <string.h>

#include "Diagnostics.h"

namespace {
constexpr uint16_t LCD_WIDTH = 368;
constexpr uint16_t LCD_HEIGHT = 448;
constexpr uint8_t LCD_ROTATION = 0;

constexpr int PIN_LCD_SDIO0 = 4;
constexpr int PIN_LCD_SDIO1 = 5;
constexpr int PIN_LCD_SDIO2 = 6;
constexpr int PIN_LCD_SDIO3 = 7;
constexpr int PIN_LCD_SCLK = 11;
constexpr int PIN_LCD_CS = 12;
constexpr int PIN_LCD_RST = -1;

constexpr int PIN_TOUCH_SDA = 15;
constexpr int PIN_TOUCH_SCL = 14;

constexpr uint8_t AMOLED_EXPANDER_I2C_ADDR = 0x20;
constexpr uint8_t AMOLED_BRIGHTNESS = 220;

constexpr uint16_t COLOR_BG = 0x0000;
constexpr uint16_t COLOR_PANEL = 0x1082;
constexpr uint16_t COLOR_PANEL_2 = 0x2104;
constexpr uint16_t COLOR_TEXT = 0xFFFF;
constexpr uint16_t COLOR_DIM = 0xBDF7;
constexpr uint16_t COLOR_ACCENT = 0x07FF;
constexpr uint16_t COLOR_GOOD = 0x07E0;
constexpr uint16_t COLOR_WARN = 0xFD20;
constexpr uint16_t COLOR_BAD = 0xF800;

constexpr int16_t PAD = 22;
constexpr int16_t HEADER_H = 58;
constexpr int16_t FOOTER_H = 42;
constexpr int16_t BODY_TOP = 82;

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

void AmoledUx::begin() {
  initPowerExpander();

  bus_ = new Arduino_ESP32QSPI(PIN_LCD_CS, PIN_LCD_SCLK, PIN_LCD_SDIO0, PIN_LCD_SDIO1,
                               PIN_LCD_SDIO2, PIN_LCD_SDIO3);
  display_ = new Arduino_SH8601(bus_, PIN_LCD_RST, LCD_ROTATION, LCD_WIDTH, LCD_HEIGHT);
  if (!display_->begin()) {
    Diagnostics::log("UX: SH8601 init failed");
    ready_ = false;
    return;
  }

  display_->setRotation(LCD_ROTATION);
  display_->setBrightness(AMOLED_BRIGHTNESS);
  display_->setTextWrap(false);
  display_->fillScreen(COLOR_BG);
  ready_ = true;
  idle();
  Diagnostics::log("UX: AMOLED ready");
}

void AmoledUx::idle() {
  Diagnostics::log("UX: idle");
  if (!ready_) return;

  returnToReadyAt_ = 0;
  drawBase("ESP32 FIDO", COLOR_ACCENT, "Lab build only");
  printText(PAD, BODY_TOP, "Authenticator", 3, COLOR_TEXT, COLOR_BG);
  printText(PAD, BODY_TOP + 54, "Waiting for USB host", 2, COLOR_DIM, COLOR_BG);
  printText(PAD, BODY_TOP + 104, "No secrets on screen", 2, COLOR_DIM, COLOR_BG);
  printText(PAD, BODY_TOP + 158, "Use test accounts only", 2, COLOR_WARN, COLOR_BG);
}

void AmoledUx::usbReady() {
  Diagnostics::log("UX: USB FIDO HID ready");
  if (!ready_) return;

  returnToReadyAt_ = 0;
  drawBase("ESP32 FIDO", COLOR_GOOD, "BOOT confirms actions");
  printText(PAD, BODY_TOP, "USB HID ready", 3, COLOR_GOOD, COLOR_BG);
  printText(PAD, BODY_TOP + 58, "Waiting for WebAuthn", 2, COLOR_TEXT, COLOR_BG);
  if (!hasTrace_) {
    printText(PAD, BODY_TOP + 108, "Register/sign-in prompts", 2, COLOR_DIM, COLOR_BG);
    printText(PAD, BODY_TOP + 136, "will appear here.", 2, COLOR_DIM, COLOR_BG);
    return;
  }
  // Surface the last request outcome as a passive trace so the operator can
  // tell real RP activity apart from synthetic/fallback host probes.
  char line[48];
  snprintf(line, sizeof(line), "Last: %s", traceCommand_);
  printClipped(PAD, BODY_TOP + 104, line, 30, 2, COLOR_DIM, COLOR_BG);
  snprintf(line, sizeof(line), "%s %s", traceSynthetic_ ? "synthetic" : "RP", traceRp_);
  printClipped(PAD, BODY_TOP + 134, line, 30, 2, traceSynthetic_ ? COLOR_WARN : COLOR_TEXT, COLOR_BG);
  snprintf(line, sizeof(line), "Status: %s", traceStatus_);
  printClipped(PAD, BODY_TOP + 164, line, 30, 2, COLOR_DIM, COLOR_BG);
}

void AmoledUx::diagnostic(const char *title, const char *line1, const char *line2) {
  Diagnostics::logf("UX: diag: %s %s %s", title ? title : "", line1 ? line1 : "",
                    line2 ? line2 : "");
  if (!ready_) return;

  drawBase(title ? title : "Diagnostic", COLOR_ACCENT, "Browser trace");
  printClipped(PAD, BODY_TOP, line1 ? line1 : "", 30, 2, COLOR_TEXT, COLOR_BG);
  if (line2 && line2[0]) {
    printClipped(PAD, BODY_TOP + 40, line2, 30, 2, COLOR_DIM, COLOR_BG);
  }
  returnToReadyAt_ = millis() + 1800;
}

void AmoledUx::diagnosticError(const char *title, const char *line1, const char *line2) {
  Diagnostics::logf("UX: diag error: %s %s %s", title ? title : "", line1 ? line1 : "",
                    line2 ? line2 : "");
  if (!ready_) return;

  drawBase(title ? title : "Rejected", COLOR_BAD, "Check settings");
  printClipped(PAD, BODY_TOP, line1 ? line1 : "", 30, 2, COLOR_BAD, COLOR_BG);
  if (line2 && line2[0]) {
    printClipped(PAD, BODY_TOP + 40, line2, 30, 2, COLOR_TEXT, COLOR_BG);
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
  copyClipped(rpLine, sizeof(rpLine), rpId && rpId[0] ? rpId : "unknown relying party", 31);

  drawBase("User Presence", COLOR_WARN, "Press BOOT to approve");
  printText(PAD, BODY_TOP, actionLine, 3, COLOR_WARN, COLOR_BG);
  printText(PAD, BODY_TOP + 62, "Relying party", 2, COLOR_DIM, COLOR_BG);
  printClipped(PAD, BODY_TOP + 94, rpLine, 31, 2, COLOR_TEXT, COLOR_BG);
  printText(PAD, BODY_TOP + 156, "Only approve requests", 2, COLOR_TEXT, COLOR_BG);
  printText(PAD, BODY_TOP + 184, "you started.", 2, COLOR_TEXT, COLOR_BG);
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
  printText(PAD, BODY_TOP, line, 2, full ? COLOR_WARN : COLOR_TEXT, COLOR_BG);

  snprintf(line, sizeof(line), "Discoverable: %u", static_cast<unsigned>(residentCredentials));
  printText(PAD, BODY_TOP + 38, line, 2, COLOR_DIM, COLOR_BG);

  snprintf(line, sizeof(line), "Free slots: %u", static_cast<unsigned>(remainingSlots));
  printText(PAD, BODY_TOP + 76, line, 2, full ? COLOR_BAD : COLOR_GOOD, COLOR_BG);

  if (full) {
    printText(PAD, BODY_TOP + 122, "Storage full", 3, COLOR_WARN, COLOR_BG);
  }

  if (awaitingConfirm) {
    printText(PAD, BODY_TOP + 176, "This wipes credentials", 2, COLOR_TEXT, COLOR_BG);
    printText(PAD, BODY_TOP + 204, "and the lab PIN.", 2, COLOR_TEXT, COLOR_BG);
  } else {
    printText(PAD, BODY_TOP + 176, "Hold BOOT again to", 2, COLOR_TEXT, COLOR_BG);
    printText(PAD, BODY_TOP + 204, "open wipe confirm.", 2, COLOR_TEXT, COLOR_BG);
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

void AmoledUx::poll() {
  if (!ready_ || returnToReadyAt_ == 0) return;
  if (static_cast<int32_t>(millis() - returnToReadyAt_) >= 0) {
    usbReady();
  }
}

void AmoledUx::drawBase(const char *title, uint16_t accentColor, const char *footer) {
  if (!ready_) return;

  display_->fillScreen(COLOR_BG);
  display_->fillRect(0, 0, LCD_WIDTH, HEADER_H, COLOR_PANEL);
  display_->fillRect(0, HEADER_H - 4, LCD_WIDTH, 4, accentColor);
  printText(PAD, 18, title, 2, COLOR_TEXT, COLOR_PANEL);

  display_->fillRect(0, LCD_HEIGHT - FOOTER_H, LCD_WIDTH, FOOTER_H, COLOR_PANEL_2);
  printText(PAD, LCD_HEIGHT - 29, footer, 2, COLOR_DIM, COLOR_PANEL_2);
}

void AmoledUx::drawStatus(const char *label, const char *message, uint16_t color) {
  if (!ready_) return;

  drawBase(label, color, "Ready for next request");
  printText(PAD, BODY_TOP, label, 3, color, COLOR_BG);
  printClipped(PAD, BODY_TOP + 66, message ? message : "", 29, 2, COLOR_TEXT, COLOR_BG);
}

void AmoledUx::printText(int16_t x, int16_t y, const char *text, uint8_t size, uint16_t color,
                         uint16_t bg) {
  if (!ready_) return;
  display_->setTextSize(size);
  display_->setTextColor(color, bg);
  display_->setCursor(x, y);
  display_->print(text ? text : "");
}

void AmoledUx::printClipped(int16_t x, int16_t y, const char *text, size_t maxChars,
                            uint8_t size, uint16_t color, uint16_t bg) {
  char line[48];
  copyClipped(line, sizeof(line), text, maxChars);
  printText(x, y, line, size, color, bg);
}

void AmoledUx::initPowerExpander() {
  Wire.begin(PIN_TOUCH_SDA, PIN_TOUCH_SCL);
  if (!expander_.begin(AMOLED_EXPANDER_I2C_ADDR, &Wire)) {
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
}
