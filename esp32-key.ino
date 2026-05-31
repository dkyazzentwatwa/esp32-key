#include <Adafruit_XCA9554.h>
#include <Arduino_GFX_Library.h>

#include "src/App.h"

Esp32KeyApp app;

void setup() {
  app.begin();
}

void loop() {
  app.loop();
}
