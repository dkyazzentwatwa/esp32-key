#include "LabRecorder.h"

#include <FS.h>
#include <SD_MMC.h>
#include <string.h>

#include "BuildConfig.h"
#include "Diagnostics.h"

namespace {
constexpr int kSdClkPin = 2;
constexpr int kSdCmdPin = 1;
constexpr int kSdD0Pin = 3;

void writeHexByte(char *out, uint8_t value) {
  static constexpr char kHex[] = "0123456789abcdef";
  out[0] = kHex[(value >> 4) & 0x0f];
  out[1] = kHex[value & 0x0f];
}
}  // namespace

void LabRecorder::begin(CryptoProvider &crypto) {
  crypto_ = &crypto;
  sdReady_ = false;
  seq_ = 0;
  sessionPath_[0] = 0;
  proofPath_[0] = 0;
  historyCount_ = 0;
  historyNext_ = 0;
  strlcpy(lastSummary_, "no events", sizeof(lastSummary_));
  setStatus("mounting");

  pinMode(kSdCmdPin, INPUT_PULLUP);
  pinMode(kSdD0Pin, INPUT_PULLUP);
  pinMode(kSdClkPin, INPUT_PULLUP);

  if (!mountAtFrequency(SDMMC_FREQ_HIGHSPEED, "40MHz") &&
      !mountAtFrequency(SDMMC_FREQ_DEFAULT, "20MHz") && !mountAtFrequency(10000, "10MHz") &&
      !mountAtFrequency(SDMMC_FREQ_PROBING, "400kHz")) {
    setStatus("SD off: mount failed");
    return;
  }

  if (SD_MMC.cardType() == CARD_NONE) {
    SD_MMC.end();
    setStatus("SD off: no card");
    return;
  }

  if (!ensureDirectory("/fido-lab") || !ensureDirectory("/fido-lab/sessions") ||
      !ensureDirectory("/fido-lab/proofs") || !chooseSessionFiles()) {
    SD_MMC.end();
    sdReady_ = false;
    setStatus("SD off: write failed");
    return;
  }

  sdReady_ = true;
  char status[48];
  snprintf(status, sizeof(status), "SD ready %lluMB",
           static_cast<unsigned long long>(SD_MMC.cardSize() / (1024ULL * 1024ULL)));
  setStatus(status);
}

bool LabRecorder::mountAtFrequency(int frequency, const char *label) {
  if (!SD_MMC.setPins(kSdClkPin, kSdCmdPin, kSdD0Pin)) {
    Diagnostics::log("LabRecorder: SD_MMC pin setup failed");
    return false;
  }
  if (SD_MMC.begin("/sdcard", true, false, frequency)) {
    Diagnostics::logf("LabRecorder: SD_MMC mounted at %s", label);
    return true;
  }
  SD_MMC.end();
  return false;
}

bool LabRecorder::ensureDirectory(const char *path) {
  if (SD_MMC.exists(path)) return true;
  return SD_MMC.mkdir(path);
}

bool LabRecorder::chooseSessionFiles() {
  for (int i = 1; i < 1000; ++i) {
    char path[48];
    snprintf(path, sizeof(path), "/fido-lab/sessions/session-%03d.jsonl", i);
    if (SD_MMC.exists(path)) continue;

    File session = SD_MMC.open(path, FILE_WRITE);
    if (!session) return false;
    session.close();
    strlcpy(sessionPath_, path, sizeof(sessionPath_));
    snprintf(proofPath_, sizeof(proofPath_), "/fido-lab/proofs/session-%03d.md", i);
    File proof = SD_MMC.open(proofPath_, FILE_WRITE);
    if (!proof) return false;
    proof.println("# ESP32 FIDO Lab Proof Bundle");
    proof.println();
    proof.println("Lab-only diagnostic artifact. Not FIDO certification or production-security proof.");
    proof.println();
    proof.print("- device: ");
    proof.println(BuildConfig::kDeviceName);
    proof.print("- firmware: ");
    proof.print(BuildConfig::kVersionMajor);
    proof.print('.');
    proof.print(BuildConfig::kVersionMinor);
    proof.print('.');
    proof.println(BuildConfig::kVersionBuild);
    proof.print("- profile_hint: ");
    proof.println(BuildConfig::kAllowSerialDiagnostics ? "debug-cdc" : "fido-lab");
    proof.print("- session_log: ");
    proof.println(sessionPath_);
    proof.println();
    proof.close();
    return true;
  }
  return false;
}

void LabRecorder::recordBoot(size_t credentialCount, size_t residentCount, bool pinSet) {
  Event event{};
  event.kind = "boot";
  event.cmd = "system";
  event.status = "started";
  event.pinSet = pinSet;
  event.residentCount = residentCount;
  event.credentialCount = credentialCount;
  event.note = BuildConfig::kDeviceName;
  record(event);
}

void LabRecorder::record(const Event &event) {
  const uint32_t seq = ++seq_;
  const uint32_t now = millis();
  updateHistory(event);
  if (!sdReady_) return;
  appendJsonl(event, seq, now);
  if (event.proof) {
    appendProof(event, seq, now);
  }
}

void LabRecorder::appendJsonl(const Event &event, uint32_t seq, uint32_t now) {
  File file = SD_MMC.open(sessionPath_, FILE_APPEND);
  if (!file) {
    setStatus("SD off: append failed");
    sdReady_ = false;
    return;
  }
  char rpLabel[48];
  char hash[20];
  redactedRp(event.rp, rpLabel, sizeof(rpLabel));
  rpHash(event.rp, hash, sizeof(hash));

  file.print('{');
  file.print("\"ms\":");
  file.print(now);
  file.print(",\"seq\":");
  file.print(seq);
  file.print(",\"kind\":");
  jsonString(file, event.kind);
  file.print(",\"cmd\":");
  jsonString(file, event.cmd);
  file.print(",\"rp\":");
  jsonString(file, rpLabel);
  file.print(",\"rp_hash\":");
  jsonString(file, hash);
  file.print(",\"status\":");
  jsonString(file, event.status);
  file.print(",\"synthetic\":");
  file.print(event.synthetic ? "true" : "false");
  file.print(",\"up\":");
  file.print(event.up ? "true" : "false");
  file.print(",\"uv\":");
  file.print(event.uv ? "true" : "false");
  file.print(",\"pin_set\":");
  file.print(event.pinSet ? "true" : "false");
  file.print(",\"resident_count\":");
  file.print(static_cast<unsigned>(event.residentCount));
  file.print(",\"credential_count\":");
  file.print(static_cast<unsigned>(event.credentialCount));
  file.print(",\"note\":");
  jsonString(file, event.note);
  file.println('}');
  file.flush();
  file.close();
}

void LabRecorder::appendProof(const Event &event, uint32_t seq, uint32_t now) {
  File file = SD_MMC.open(proofPath_, FILE_APPEND);
  if (!file) return;
  char rpLabel[48];
  char hash[20];
  redactedRp(event.rp, rpLabel, sizeof(rpLabel));
  rpHash(event.rp, hash, sizeof(hash));

  file.print("## Event ");
  file.println(seq);
  file.println();
  file.print("- ms: ");
  file.println(now);
  file.print("- command: ");
  file.println(event.cmd ? event.cmd : "");
  file.print("- relying_party: ");
  file.println(rpLabel);
  file.print("- rp_hash: ");
  file.println(hash);
  file.print("- status: ");
  file.println(event.status ? event.status : "");
  file.print("- proof_level: lab functional event, not certification");
  file.println();
  file.print("- counts: credentials=");
  file.print(static_cast<unsigned>(event.credentialCount));
  file.print(" resident=");
  file.println(static_cast<unsigned>(event.residentCount));
  file.print("- note: ");
  file.println(event.note ? event.note : "");
  file.println();
  file.close();
}

void LabRecorder::setStatus(const char *status) {
  strlcpy(statusLine_, status ? status : "-", sizeof(statusLine_));
  Diagnostics::logf("LabRecorder: %s", statusLine_);
}

void LabRecorder::updateHistory(const Event &event) {
  char rpLabel[32];
  redactedRp(event.rp, rpLabel, sizeof(rpLabel));
  snprintf(lastSummary_, sizeof(lastSummary_), "%s %s %s", event.cmd ? event.cmd : "-",
           rpLabel[0] ? rpLabel : "-", event.status ? event.status : "-");
  strlcpy(history_[historyNext_], lastSummary_, sizeof(history_[historyNext_]));
  historyNext_ = (historyNext_ + 1) % kHistoryDepth;
  if (historyCount_ < kHistoryDepth) historyCount_++;
}

void LabRecorder::redactedRp(const char *rp, char *out, size_t outLen) {
  if (!outLen) return;
  if (!rp || !rp[0]) {
    strlcpy(out, "", outLen);
    return;
  }
  if (isFullRpAllowed(rp)) {
    strlcpy(out, rp, outLen);
  } else {
    strlcpy(out, "redacted", outLen);
  }
}

void LabRecorder::rpHash(const char *rp, char *out, size_t outLen) {
  if (!outLen) return;
  out[0] = 0;
  if (!rp || !rp[0] || !crypto_) return;
  uint8_t digest[32];
  if (!crypto_->sha256(reinterpret_cast<const uint8_t *>(rp), strlen(rp), digest)) return;
  const size_t bytes = min(static_cast<size_t>(8), (outLen - 1) / 2);
  for (size_t i = 0; i < bytes; ++i) {
    writeHexByte(out + i * 2, digest[i]);
  }
  out[bytes * 2] = 0;
}

void LabRecorder::jsonString(File &file, const char *value) {
  file.print('"');
  if (value) {
    for (const char *p = value; *p; ++p) {
      if (*p == '"' || *p == '\\') {
        file.print('\\');
        file.print(*p);
      } else if (static_cast<uint8_t>(*p) < 0x20) {
        file.print(' ');
      } else {
        file.print(*p);
      }
    }
  }
  file.print('"');
}

bool LabRecorder::isFullRpAllowed(const char *rp) const {
  return strcmp(rp, "webauthn.io") == 0 || strcmp(rp, ".dummy") == 0;
}
