#include "Diagnostics.h"

#include <stdarg.h>

#include "BuildConfig.h"

namespace Diagnostics {

void begin() {
  Serial.begin(115200);
  Serial.setDebugOutput(BuildConfig::kAllowSerialDiagnostics);
}

void log(const char *message) {
  if (BuildConfig::kAllowSerialDiagnostics) {
    Serial.println(message);
  }
}

void logf(const char *fmt, ...) {
  if constexpr (!BuildConfig::kAllowSerialDiagnostics) {
    return;
  }
  char line[192];
  va_list args;
  va_start(args, fmt);
  vsnprintf(line, sizeof(line), fmt, args);
  va_end(args);
  Serial.println(line);
}

}  // namespace Diagnostics
