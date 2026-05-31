#pragma once

#include <Arduino.h>

namespace BuildConfig {
constexpr const char *kDeviceName = "ESP32-S3 AMOLED FIDO Lab Key";
constexpr const char *kManufacturer = "Cypher Lab";
constexpr uint8_t kVersionMajor = 0;
constexpr uint8_t kVersionMinor = 1;
constexpr uint8_t kVersionBuild = 0;
constexpr uint8_t kBootButtonPin = 0;
constexpr size_t kHidReportSize = 64;
constexpr size_t kMaxCtapMessageSize = 1024;
constexpr size_t kMaxCredentials = 8;
constexpr uint32_t kUserPresenceTimeoutMs = 30000;
constexpr uint32_t kResetHoldMs = 5000;
constexpr uint32_t kAdminOpenHoldMs = 1800;
constexpr uint32_t kAdminConfirmHoldMs = 5000;
constexpr uint32_t kAdminConfirmTimeoutMs = 15000;
constexpr bool kAllowSerialDiagnostics =
#if ARDUHAL_LOG_LEVEL > 0
    true;
#else
    false;
#endif
}  // namespace BuildConfig
