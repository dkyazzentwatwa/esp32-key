#include "MasterSecret.h"

#include <string.h>

namespace {
constexpr char kNamespace[] = "fido_ms";
constexpr char kSecretKey[] = "k";
constexpr char kCounterKey[] = "sc";
// Distinct, versioned HKDF info labels so the three sub-keys are cryptographically
// independent. Never reuse the master secret directly for crypto.
constexpr char kSeedLabel[] = "esp32key/seed/v1";
constexpr char kMacLabel[] = "esp32key/mac/v1";
constexpr char kCredRandomLabel[] = "fido2-credrandom-v1";
}  // namespace

void MasterSecret::begin(CryptoProvider &crypto) {
  crypto_ = &crypto;
  prefs_.begin(kNamespace, false);
  ensureSecret();
}

bool MasterSecret::ensureSecret() {
  if (!crypto_) return false;
  if (prefs_.getBytesLength(kSecretKey) == sizeof(master_) &&
      prefs_.getBytes(kSecretKey, master_, sizeof(master_)) == sizeof(master_)) {
    ready_ = true;
    return true;
  }
  if (!crypto_->randomBytes(master_, sizeof(master_))) {
    ready_ = false;
    return false;
  }
  prefs_.putBytes(kSecretKey, master_, sizeof(master_));
  ready_ = true;
  return true;
}

bool MasterSecret::deriveSubKey(const char *label, size_t labelLen, uint8_t out[32]) {
  if (!ready_ || !crypto_) return false;
  return crypto_->hkdfSha256(master_, sizeof(master_), reinterpret_cast<const uint8_t *>(label), labelLen, out);
}

bool MasterSecret::deriveSeedKey(uint8_t out[32]) {
  return deriveSubKey(kSeedLabel, sizeof(kSeedLabel) - 1, out);
}

bool MasterSecret::deriveMacKey(uint8_t out[32]) {
  return deriveSubKey(kMacLabel, sizeof(kMacLabel) - 1, out);
}

bool MasterSecret::deriveCredRandomKey(uint8_t out[32]) {
  return deriveSubKey(kCredRandomLabel, sizeof(kCredRandomLabel) - 1, out);
}

uint32_t MasterSecret::currentSignCount() {
  return prefs_.getUInt(kCounterKey, 0);
}

uint32_t MasterSecret::nextSignCount() {
  const uint32_t next = currentSignCount() + 1;
  prefs_.putUInt(kCounterKey, next);
  return next;
}

void MasterSecret::wipe() {
  prefs_.remove(kSecretKey);
  prefs_.remove(kCounterKey);
  memset(master_, 0, sizeof(master_));
  ready_ = false;
  // Regenerate immediately so the device stays usable; the new secret makes
  // every previously-issued stateless credential ID fail its MAC check.
  ensureSecret();
}
