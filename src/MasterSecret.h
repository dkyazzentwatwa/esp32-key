#pragma once

#include <Arduino.h>
#include <Preferences.h>

#include "CryptoProvider.h"

// Device master secret for stateless credential key-wrapping plus the global
// signature counter. The master secret never leaves the device and is used
// only as HKDF input material; callers receive domain-separated sub-keys, never
// the master itself. Wiping it (factory reset / admin wipe) rotates every
// sub-key and therefore cryptographically invalidates every outstanding
// stateless credential ID at once.
class MasterSecret {
 public:
  void begin(CryptoProvider &crypto);
  // Domain-separated 32-byte sub-keys derived via HKDF from the master secret.
  bool deriveSeedKey(uint8_t out[32]);        // wraps the per-credential private key
  bool deriveMacKey(uint8_t out[32]);         // authenticates the credential ID
  bool deriveCredRandomKey(uint8_t out[32]);  // hmac-secret CredRandom (Phase 2)
  uint32_t currentSignCount();
  uint32_t nextSignCount();  // increment + persist, returns the new value
  void wipe();               // erase + regenerate the secret, reset the counter

 private:
  bool ensureSecret();
  bool deriveSubKey(const char *label, size_t labelLen, uint8_t out[32]);

  CryptoProvider *crypto_ = nullptr;
  Preferences prefs_;
  uint8_t master_[32] = {};
  bool ready_ = false;
};
