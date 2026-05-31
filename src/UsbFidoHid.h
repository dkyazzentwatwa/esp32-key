#pragma once

#include <Arduino.h>

#include "BuildConfig.h"
#include "CtapHid.h"

class UsbFidoHid {
 public:
  explicit UsbFidoHid(CtapHid &ctap);
  void begin();
  void poll();
  bool sendPacket(const uint8_t packet[BuildConfig::kHidReportSize]);

 private:
  static bool sendThunk(void *ctx, const uint8_t packet[BuildConfig::kHidReportSize]);
  CtapHid &ctap_;
};
