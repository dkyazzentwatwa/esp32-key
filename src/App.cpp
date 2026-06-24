#include "App.h"

#include "BuildConfig.h"
#include "Diagnostics.h"

Esp32KeyApp::Esp32KeyApp()
    : ctap2_(crypto_, store_, presence_, ux_, recorder_), ctapHid_(ctap2_, ux_, recorder_), usb_(ctapHid_) {}

void Esp32KeyApp::begin() {
  Diagnostics::begin();
  Serial.printf("%s boot marker\n", BuildConfig::kDeviceName);
  Diagnostics::logf("%s boot", BuildConfig::kDeviceName);
  presence_.begin();
  ux_.begin();
  crypto_.begin();
  store_.begin();
  ctap2_.begin();
  recorder_.begin(crypto_);
  recorder_.recordBoot(store_.count(), store_.residentCount(), ctap2_.isPinSet());
  ux_.recorderStatus(recorder_.statusLine(), recorder_.lastSummary());
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
    LabRecorder::Event event{};
    event.kind = "proof";
    event.cmd = "adminWipe";
    event.status = "wiped 0x00";
    event.pinSet = ctap2_.isPinSet();
    event.residentCount = store_.residentCount();
    event.credentialCount = store_.count();
    event.note = "local BOOT admin wipe";
    event.proof = true;
    recorder_.record(event);
    ux_.recorderStatus(recorder_.statusLine(), recorder_.lastSummary());
    adminState_ = AdminState::kReady;
    bootHeldSince_ = now;
    ux_.success("Admin Wiped");
  }
}
