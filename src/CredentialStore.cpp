#include "CredentialStore.h"

#include <string.h>

void CredentialStore::begin() {
  prefs_.begin("fido", false);
  count_ = prefs_.getUInt("count", 0);
  if (count_ > BuildConfig::kMaxCredentials) {
    wipe();
    return;
  }
  compact();
}

size_t CredentialStore::count() const {
  return count_;
}

size_t CredentialStore::remainingSlots() const {
  return count_ < BuildConfig::kMaxCredentials ? BuildConfig::kMaxCredentials - count_ : 0;
}

size_t CredentialStore::residentCount() {
  size_t total = 0;
  for (size_t i = 0; i < count_; ++i) {
    CredentialRecord record;
    if (load(i, record) && (record.flags & kCredentialFlagResident)) {
      total++;
    }
  }
  return total;
}

String CredentialStore::keyFor(size_t index) const {
  char key[12];
  snprintf(key, sizeof(key), "cred%u", static_cast<unsigned>(index));
  return String(key);
}

uint32_t CredentialStore::checksumFor(const CredentialRecord &record) {
  CredentialRecord copy = record;
  copy.checksum = 0;
  const uint8_t *data = reinterpret_cast<const uint8_t *>(&copy);
  uint32_t hash = 2166136261UL;
  for (size_t i = 0; i < sizeof(CredentialRecord); ++i) {
    hash ^= data[i];
    hash *= 16777619UL;
  }
  return hash;
}

bool CredentialStore::isValid(const CredentialRecord &record) {
  return record.magic == kCredentialRecordMagic && record.version == kCredentialRecordVersion &&
         record.userHandleLen <= sizeof(record.userHandle) && record.checksum == checksumFor(record);
}

CredentialRecord CredentialStore::withChecksum(const CredentialRecord &record) {
  CredentialRecord copy = record;
  copy.magic = kCredentialRecordMagic;
  copy.version = kCredentialRecordVersion;
  copy.checksum = 0;
  copy.checksum = checksumFor(copy);
  return copy;
}

bool CredentialStore::loadRaw(size_t index, CredentialRecord &record) {
  if (index >= count_) {
    return false;
  }
  const String key = keyFor(index);
  if (prefs_.getBytesLength(key.c_str()) != sizeof(CredentialRecord)) {
    return false;
  }
  return prefs_.getBytes(key.c_str(), &record, sizeof(record)) == sizeof(record);
}

bool CredentialStore::load(size_t index, CredentialRecord &record) {
  return loadRaw(index, record) && isValid(record);
}

bool CredentialStore::save(size_t index, const CredentialRecord &record) {
  if (index >= BuildConfig::kMaxCredentials || record.magic != kCredentialRecordMagic ||
      record.version != kCredentialRecordVersion) {
    return false;
  }
  const String key = keyFor(index);
  const CredentialRecord checked = withChecksum(record);
  return prefs_.putBytes(key.c_str(), &checked, sizeof(checked)) == sizeof(checked);
}

bool CredentialStore::add(const CredentialRecord &record) {
  if (record.magic != kCredentialRecordMagic || record.version != kCredentialRecordVersion) {
    return false;
  }
  if (count_ >= BuildConfig::kMaxCredentials) {
    return false;
  }
  if (!save(count_, record)) {
    return false;
  }
  count_++;
  prefs_.putUInt("count", count_);
  return true;
}

bool CredentialStore::findByCredentialId(const uint8_t *credentialId, size_t credentialIdLen, CredentialRecord &record, size_t *index) {
  if (!credentialId || credentialIdLen != 32) {
    return false;
  }
  for (size_t i = 0; i < count_; ++i) {
    CredentialRecord candidate;
    if (load(i, candidate) && memcmp(candidate.credentialId, credentialId, 32) == 0) {
      record = candidate;
      if (index) *index = i;
      return true;
    }
  }
  return false;
}

bool CredentialStore::findByRpIdHashAndAllowList(const uint8_t rpIdHash[32], const uint8_t *credentialId, size_t credentialIdLen, CredentialRecord &record, size_t *index) {
  if (!findByCredentialId(credentialId, credentialIdLen, record, index)) {
    return false;
  }
  return memcmp(record.rpIdHash, rpIdHash, 32) == 0;
}

size_t CredentialStore::collectByRpIdHash(const uint8_t rpIdHash[32], bool residentOnly, size_t *indexes, size_t maxIndexes) {
  size_t found = 0;
  for (size_t i = 0; i < count_ && found < maxIndexes; ++i) {
    CredentialRecord candidate;
    if (load(i, candidate) && memcmp(candidate.rpIdHash, rpIdHash, 32) == 0 &&
        (!residentOnly || (candidate.flags & kCredentialFlagResident))) {
      indexes[found++] = i;
    }
  }
  return found;
}

bool CredentialStore::remove(size_t index) {
  if (index >= count_) {
    return false;
  }
  prefs_.remove(keyFor(index).c_str());
  compact();
  return true;
}

bool CredentialStore::removeByCredentialId(const uint8_t *credentialId, size_t credentialIdLen) {
  CredentialRecord record;
  size_t index = 0;
  if (!findByCredentialId(credentialId, credentialIdLen, record, &index)) {
    return false;
  }
  return remove(index);
}

bool CredentialStore::update(size_t index, const CredentialRecord &record) {
  if (index >= count_) {
    return false;
  }
  return save(index, record);
}

bool CredentialStore::updateCounter(size_t index, uint32_t signCount) {
  CredentialRecord record;
  if (!load(index, record)) {
    return false;
  }
  record.signCount = signCount;
  return save(index, record);
}

void CredentialStore::wipe() {
  for (size_t i = 0; i < BuildConfig::kMaxCredentials; ++i) {
    prefs_.remove(keyFor(i).c_str());
  }
  count_ = 0;
  prefs_.putUInt("count", 0);
}

void CredentialStore::compact() {
  size_t writeIndex = 0;
  for (size_t readIndex = 0; readIndex < count_; ++readIndex) {
    CredentialRecord record;
    if (!load(readIndex, record)) {
      prefs_.remove(keyFor(readIndex).c_str());
      continue;
    }
    if (writeIndex != readIndex) {
      save(writeIndex, record);
      prefs_.remove(keyFor(readIndex).c_str());
    }
    writeIndex++;
  }
  for (size_t i = writeIndex; i < BuildConfig::kMaxCredentials; ++i) {
    prefs_.remove(keyFor(i).c_str());
  }
  count_ = writeIndex;
  prefs_.putUInt("count", count_);
}

CredentialRecord makeEmptyCredentialRecord() {
  CredentialRecord record{};
  record.magic = kCredentialRecordMagic;
  record.version = kCredentialRecordVersion;
  return record;
}
