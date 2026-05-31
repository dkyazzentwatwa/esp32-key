#pragma once

#include <Arduino.h>

namespace Diagnostics {
void begin();
void log(const char *message);
void logf(const char *fmt, ...);
}  // namespace Diagnostics
