#pragma once

#include <Arduino.h>
#include <Preferences.h>

#include "BuildConfig.h"

constexpr uint32_t kCredentialRecordMagic = 0x4649444f;  // FIDO
constexpr uint16_t kCredentialRecordVersion = 2;
constexpr uint16_t kCredentialFlagResident = 0x0001;

struct CredentialRecord {
  uint32_t magic;
  uint16_t version;
  uint16_t flags;
  uint8_t credentialId[32];
  uint8_t rpIdHash[32];
  char rpId[64];
  char rpName[48];
  uint8_t userHandle[64];
  uint8_t userHandleLen;
  char userName[48];
  char userDisplayName[48];
  uint8_t privateKey[32];
  uint8_t publicX[32];
  uint8_t publicY[32];
  uint32_t signCount;
  uint32_t checksum;
};

class CredentialStore {
 public:
  void begin();
  bool add(const CredentialRecord &record);
  bool load(size_t index, CredentialRecord &record);
  bool findByCredentialId(const uint8_t *credentialId, size_t credentialIdLen, CredentialRecord &record, size_t *index = nullptr);
  bool findByRpIdHashAndAllowList(const uint8_t rpIdHash[32], const uint8_t *credentialId, size_t credentialIdLen, CredentialRecord &record, size_t *index = nullptr);
  size_t collectByRpIdHash(const uint8_t rpIdHash[32], bool residentOnly, size_t *indexes, size_t maxIndexes);
  bool remove(size_t index);
  bool removeByCredentialId(const uint8_t *credentialId, size_t credentialIdLen);
  bool update(size_t index, const CredentialRecord &record);
  bool updateCounter(size_t index, uint32_t signCount);
  void wipe();
  size_t count() const;
  size_t residentCount();
  size_t remainingSlots() const;

 private:
  bool loadRaw(size_t index, CredentialRecord &record);
  bool save(size_t index, const CredentialRecord &record);
  void compact();
  String keyFor(size_t index) const;
  static uint32_t checksumFor(const CredentialRecord &record);
  static bool isValid(const CredentialRecord &record);
  static CredentialRecord withChecksum(const CredentialRecord &record);

  Preferences prefs_;
  size_t count_ = 0;
};
