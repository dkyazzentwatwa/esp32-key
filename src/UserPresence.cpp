#include "UserPresence.h"

#include "BuildConfig.h"

void UserPresence::begin() {
  pinMode(BuildConfig::kBootButtonPin, INPUT_PULLUP);
}

bool UserPresence::readPressed() const {
  return digitalRead(BuildConfig::kBootButtonPin) == LOW;
}

bool UserPresence::isPressed() const {
  return readPressed();
}

bool UserPresence::waitForPress(uint32_t timeoutMs) {
  const uint32_t started = millis();
  while (readPressed() && millis() - started < 500) {
    delay(5);
  }
  while (millis() - started < timeoutMs) {
    if (readPressed()) {
      delay(25);
      return readPressed();
    }
    delay(5);
  }
  return false;
}

bool UserPresence::waitForResetHold(uint32_t holdMs, uint32_t timeoutMs) {
  const uint32_t started = millis();
  uint32_t heldSince = 0;
  while (millis() - started < timeoutMs) {
    if (readPressed()) {
      if (heldSince == 0) {
        heldSince = millis();
      }
      if (millis() - heldSince >= holdMs) {
        return true;
      }
    } else {
      heldSince = 0;
    }
    delay(10);
  }
  return false;
}
