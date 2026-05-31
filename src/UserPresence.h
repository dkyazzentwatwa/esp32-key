#pragma once

#include <Arduino.h>

class UserPresence {
 public:
  void begin();
  bool waitForPress(uint32_t timeoutMs);
  bool waitForResetHold(uint32_t holdMs, uint32_t timeoutMs);
  bool isPressed() const;

 private:
  bool readPressed() const;
};
