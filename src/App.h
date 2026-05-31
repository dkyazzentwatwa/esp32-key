#pragma once

#include <Arduino.h>

#include "AmoledUx.h"
#include "CredentialStore.h"
#include "CryptoProvider.h"
#include "Ctap2.h"
#include "CtapHid.h"
#include "UsbFidoHid.h"
#include "UserPresence.h"

class Esp32KeyApp {
 public:
  Esp32KeyApp();
  void begin();
  void loop();

 private:
  void handleAdminButton();
  void showAdminStatus(bool awaitingConfirm);

  enum class AdminState : uint8_t {
    kReady,
    kConfirm,
  };

  CryptoProvider crypto_;
  CredentialStore store_;
  UserPresence presence_;
  AmoledUx ux_;
  Ctap2 ctap2_;
  CtapHid ctapHid_;
  UsbFidoHid usb_;
  AdminState adminState_ = AdminState::kReady;
  uint32_t bootHeldSince_ = 0;
  uint32_t adminConfirmStarted_ = 0;
  bool bootWasPressed_ = false;
  bool adminNeedsRelease_ = false;
};
