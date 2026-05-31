#include "App.h"

#include "BuildConfig.h"
#include "Diagnostics.h"

Esp32KeyApp::Esp32KeyApp() : ctap2_(crypto_, store_, presence_, ux_), ctapHid_(ctap2_, ux_), usb_(ctapHid_) {}

void Esp32KeyApp::begin() {
  Diagnostics::begin();
  Serial.println("ESP32-S3 AMOLED FIDO lab key boot marker");
  Diagnostics::log("ESP32-S3 AMOLED FIDO lab key boot");
  presence_.begin();
  ux_.begin();
  crypto_.begin();
  store_.begin();
  ctap2_.begin();
  usb_.begin();
  ux_.usbReady();
}

void Esp32KeyApp::loop() {
  usb_.poll();
  ux_.poll();
  handleAdminButton();
  delay(1);
}

void Esp32KeyApp::showAdminStatus(bool awaitingConfirm) {
  ux_.adminStatus(store_.count(), store_.residentCount(), store_.remainingSlots(), awaitingConfirm);
}

void Esp32KeyApp::handleAdminButton() {
  const bool pressed = presence_.isPressed();
  const uint32_t now = millis();

  if (!pressed) {
    bootHeldSince_ = 0;
    bootWasPressed_ = false;
    adminNeedsRelease_ = false;
    if (adminState_ == AdminState::kConfirm &&
        static_cast<int32_t>(now - (adminConfirmStarted_ + BuildConfig::kAdminConfirmTimeoutMs)) >= 0) {
      adminState_ = AdminState::kReady;
      ux_.usbReady();
    }
    return;
  }

  if (adminNeedsRelease_) {
    return;
  }

  if (!bootWasPressed_) {
    bootWasPressed_ = true;
    bootHeldSince_ = now;
    return;
  }

  const uint32_t heldMs = now - bootHeldSince_;

  if (adminState_ == AdminState::kReady && heldMs >= BuildConfig::kAdminOpenHoldMs) {
    adminState_ = AdminState::kConfirm;
    adminConfirmStarted_ = now;
    showAdminStatus(true);
    adminNeedsRelease_ = true;
    return;
  }

  if (adminState_ == AdminState::kConfirm && heldMs >= BuildConfig::kAdminConfirmHoldMs) {
    ctap2_.wipeLabState();
    adminState_ = AdminState::kReady;
    bootHeldSince_ = now;
    ux_.success("Admin Wiped");
  }
}
