#pragma once

#include <Arduino.h>
#include <FS.h>

#include "CryptoProvider.h"

class LabRecorder {
 public:
  struct Event {
    const char *kind = "";
    const char *cmd = "";
    const char *rp = "";
    const char *status = "";
    bool synthetic = false;
    bool up = false;
    bool uv = false;
    bool pinSet = false;
    size_t residentCount = 0;
    size_t credentialCount = 0;
    const char *note = "";
    bool proof = false;
  };

  void begin(CryptoProvider &crypto);
  bool available() const { return sdReady_; }
  const char *statusLine() const { return statusLine_; }
  const char *lastSummary() const { return lastSummary_; }
  const char *sessionPath() const { return sessionPath_; }
  const char *proofPath() const { return proofPath_; }

  void record(const Event &event);
  void recordBoot(size_t credentialCount, size_t residentCount, bool pinSet);

 private:
  static constexpr size_t kHistoryDepth = 12;

  bool mountAtFrequency(int frequency, const char *label);
  bool ensureDirectory(const char *path);
  bool chooseSessionFiles();
  void appendJsonl(const Event &event, uint32_t seq, uint32_t now);
  void appendProof(const Event &event, uint32_t seq, uint32_t now);
  void setStatus(const char *status);
  void updateHistory(const Event &event);
  void redactedRp(const char *rp, char *out, size_t outLen);
  void rpHash(const char *rp, char *out, size_t outLen);
  void jsonString(File &file, const char *value);
  bool isFullRpAllowed(const char *rp) const;

  CryptoProvider *crypto_ = nullptr;
  bool sdReady_ = false;
  uint32_t seq_ = 0;
  char statusLine_[48] = "not initialized";
  char sessionPath_[48] = "";
  char proofPath_[48] = "";
  char history_[kHistoryDepth][72] = {};
  size_t historyCount_ = 0;
  size_t historyNext_ = 0;
  char lastSummary_[72] = "no events";
};
