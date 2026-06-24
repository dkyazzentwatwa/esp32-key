#pragma once

#include <Arduino.h>
#include <Adafruit_XCA9554.h>
#include <Arduino_GFX_Library.h>

#include "BoardProfile.h"

#if defined(ESP32_KEY_BOARD_TOUCH_LCD147)
#include <Adafruit_ST7789.h>
#include <SPI.h>

class Esp32KeyST7789 : public Adafruit_ST7789 {
 public:
  Esp32KeyST7789(SPIClass *spiClass, int8_t cs, int8_t dc, int8_t rst)
      : Adafruit_ST7789(spiClass, cs, dc, rst) {}

  using Adafruit_ST7789::setColRowStart;
  void applyMadctlFix(uint8_t rotation, bool mirrorX, bool mirrorY);
};
#endif

class AmoledUx {
 public:
  void begin();
  void poll();
  void idle();
  void usbReady();
  void diagnostic(const char *title, const char *line1, const char *line2 = nullptr);
  void diagnosticError(const char *title, const char *line1, const char *line2 = nullptr);
  void waitingForPresence(const char *action, const char *rpId);
  void adminStatus(size_t totalCredentials, size_t residentCredentials, size_t remainingSlots,
                   bool awaitingConfirm);
  void success(const char *message);
  void error(const char *message);
  // Log-only trace of the last CTAP request outcome. Never draws to the screen
  // or schedules a return-to-ready, so it is safe to call for silent/synthetic
  // host probes (e.g. .dummy or up=false pre-flight) without disturbing an
  // active real-RP prompt. The recorded values surface on the usbReady screen.
  void trace(const char *command, const char *rpId, const char *status, bool synthetic);
  // Passive SD recorder state for ready/admin screens. This does not repaint
  // immediately, so recorder events cannot interrupt browser prompts.
  void recorderStatus(const char *status, const char *lastEvent);

 private:
  void drawBase(const char *title, uint16_t accentColor, const char *footer);
  void drawStatus(const char *label, const char *message, uint16_t color);
  void printText(int16_t x, int16_t y, const char *text, uint8_t size, uint16_t color,
                 uint16_t bg);
  void printClipped(int16_t x, int16_t y, const char *text, size_t maxChars, uint8_t size,
                    uint16_t color, uint16_t bg);
  bool initDisplay();
  void initAmoledPowerExpander();
  bool beginDisplay();
  void setDisplayRotation(uint8_t rotation);
  void setDisplayTextWrap(bool wrap);
  void displayFillScreen(uint16_t color);
  void displayFillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color);
  void displaySetTextSize(uint8_t size);
  void displaySetTextColor(uint16_t color, uint16_t bg);
  void displaySetCursor(int16_t x, int16_t y);
  void displayPrint(const char *text);

  Arduino_DataBus *bus_ = nullptr;
#if defined(ESP32_KEY_BOARD_AMOLED18)
  Arduino_SH8601 *amoled_ = nullptr;
#elif defined(ESP32_KEY_BOARD_TOUCH_LCD147)
  Esp32KeyST7789 *lcd_ = nullptr;
#endif
  Arduino_GFX *display_ = nullptr;
  Adafruit_XCA9554 expander_;
  uint32_t returnToReadyAt_ = 0;
  bool ready_ = false;
  char traceCommand_[20] = "";
  char traceRp_[40] = "";
  char traceStatus_[24] = "";
  bool traceSynthetic_ = false;
  bool hasTrace_ = false;
  char recorderStatus_[40] = "";
  char recorderLast_[56] = "";
  bool hasRecorderStatus_ = false;
};
