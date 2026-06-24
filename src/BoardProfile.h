#pragma once

#include <Arduino.h>

namespace BoardProfile {

#if defined(ARDUINO_WAVESHARE_ESP32_S3_TOUCH_AMOLED_18)
#define ESP32_KEY_BOARD_AMOLED18 1
constexpr const char *kBoardName = "Waveshare ESP32-S3-Touch-AMOLED-1.8";
constexpr const char *kProfileSuffix = "amoled18";
constexpr bool kSmallDisplay = false;
constexpr uint16_t kDisplayWidth = 368;
constexpr uint16_t kDisplayHeight = 448;
constexpr uint8_t kDisplayRotation = 0;
constexpr int kAmoledSdio0 = 4;
constexpr int kAmoledSdio1 = 5;
constexpr int kAmoledSdio2 = 6;
constexpr int kAmoledSdio3 = 7;
constexpr int kDisplaySclk = 11;
constexpr int kDisplayCs = 12;
constexpr int kDisplayRst = -1;
constexpr int kI2cSda = 15;
constexpr int kI2cScl = 14;
constexpr uint8_t kAmoledExpanderAddr = 0x20;
constexpr uint8_t kAmoledBrightness = 220;
#elif defined(ARDUINO_ESP32S3_DEV)
#define ESP32_KEY_BOARD_TOUCH_LCD147 1
constexpr const char *kBoardName = "Waveshare ESP32-S3-Touch-LCD-1.47";
constexpr const char *kProfileSuffix = "touch-lcd147";
constexpr bool kSmallDisplay = true;
constexpr uint16_t kDisplayWidth = 172;
constexpr uint16_t kDisplayHeight = 320;
constexpr uint8_t kDisplayRotation = 2;
constexpr int kDisplaySclk = 38;
constexpr int kDisplayMosi = 39;
constexpr int kDisplayCs = 21;
constexpr int kDisplayDc = 45;
constexpr int kDisplayRst = 40;
constexpr int kDisplayBacklight = 46;
constexpr uint8_t kDisplayColOffset = 34;
constexpr uint8_t kDisplayRowOffset = 0;
constexpr int kTouchSda = 42;
constexpr int kTouchScl = 41;
constexpr int kTouchRst = 47;
constexpr int kTouchInt = 48;
#else
#error Unsupported board profile. Use fido-lab, debug-cdc, fido-lab-147, or debug-cdc-147.
#endif

constexpr uint8_t kBootButtonPin = 0;

}  // namespace BoardProfile
