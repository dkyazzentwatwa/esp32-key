#include "Ctap2.h"

#include <string.h>

#include "BuildConfig.h"
#include "Diagnostics.h"

static constexpr uint8_t kCmdMakeCredential = 0x01;
static constexpr uint8_t kCmdGetAssertion = 0x02;
static constexpr uint8_t kCmdGetInfo = 0x04;
static constexpr uint8_t kCmdClientPin = 0x06;
static constexpr uint8_t kCmdReset = 0x07;
static constexpr uint8_t kCmdGetNextAssertion = 0x08;
static constexpr uint8_t kCmdCredentialManagement = 0x0a;

static constexpr uint8_t kCredMgmtGetCredsMetadata = 0x01;
static constexpr uint8_t kCredMgmtEnumerateRpsBegin = 0x02;
static constexpr uint8_t kCredMgmtEnumerateRpsGetNextRp = 0x03;
static constexpr uint8_t kCredMgmtEnumerateCredentialsBegin = 0x04;
static constexpr uint8_t kCredMgmtEnumerateCredentialsGetNextCredential = 0x05;
static constexpr uint8_t kCredMgmtDeleteCredential = 0x06;
static constexpr uint8_t kCredMgmtUpdateUserInformation = 0x07;

static constexpr uint8_t kClientPinGetRetries = 0x01;
static constexpr uint8_t kClientPinGetKeyAgreement = 0x02;
static constexpr uint8_t kClientPinSetPin = 0x03;
static constexpr uint8_t kClientPinChangePin = 0x04;
static constexpr uint8_t kClientPinGetPinToken = 0x05;
static constexpr uint8_t kClientPinGetTokenWithPermissions = 0x09;
static constexpr uint8_t kPinProtocolTwo = 2;
static constexpr uint8_t kPinMaxRetries = 8;
static constexpr uint8_t kPinPermissionMakeCredential = 0x01;
static constexpr uint8_t kPinPermissionGetAssertion = 0x02;

static constexpr uint8_t kU2fRegister = 0x01;
static constexpr uint8_t kU2fAuthenticate = 0x02;
static constexpr uint8_t kU2fVersion = 0x03;
static constexpr uint16_t kU2fSwNoError = 0x9000;
static constexpr uint16_t kU2fSwConditionsNotSatisfied = 0x6985;
static constexpr uint16_t kU2fSwWrongData = 0x6a80;
static constexpr uint16_t kU2fSwWrongLength = 0x6700;
static constexpr uint16_t kU2fSwClaNotSupported = 0x6e00;
static constexpr uint16_t kU2fSwInsNotSupported = 0x6d00;

// Public sample attestation key/certificate from the FIDO U2F raw message
// examples. This keeps the lab build browser-compatible without making any
// production attestation claim.
static const uint8_t kU2fAttestationPrivateKey[32] = {
    0xf3, 0xfc, 0xcc, 0x0d, 0x00, 0xd8, 0x03, 0x19, 0x54, 0xf9, 0x08,
    0x64, 0xd4, 0x3c, 0x24, 0x7f, 0x4b, 0xf5, 0xf0, 0x66, 0x5c, 0x6b,
    0x50, 0xcc, 0x17, 0x74, 0x9a, 0x27, 0xd1, 0xcf, 0x76, 0x64};

static const uint8_t kU2fAttestationCert[] = {
    0x30, 0x82, 0x01, 0x3c, 0x30, 0x81, 0xe4, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x0a, 0x47, 0x90, 0x12, 0x80, 0x00, 0x11, 0x55, 0x95,
    0x73, 0x52, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x13, 0x0c, 0x47, 0x6e, 0x75, 0x62, 0x62, 0x79,
    0x20, 0x50, 0x69, 0x6c, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x31,
    0x32, 0x30, 0x38, 0x31, 0x34, 0x31, 0x38, 0x32, 0x39, 0x33, 0x32,
    0x5a, 0x17, 0x0d, 0x31, 0x33, 0x30, 0x38, 0x31, 0x34, 0x31, 0x38,
    0x32, 0x39, 0x33, 0x32, 0x5a, 0x30, 0x31, 0x31, 0x2f, 0x30, 0x2d,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x26, 0x50, 0x69, 0x6c, 0x6f,
    0x74, 0x47, 0x6e, 0x75, 0x62, 0x62, 0x79, 0x2d, 0x30, 0x2e, 0x34,
    0x2e, 0x31, 0x2d, 0x34, 0x37, 0x39, 0x30, 0x31, 0x32, 0x38, 0x30,
    0x30, 0x30, 0x31, 0x31, 0x35, 0x35, 0x39, 0x35, 0x37, 0x33, 0x35,
    0x32, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x8d, 0x61, 0x7e, 0x65, 0xc9,
    0x50, 0x8e, 0x64, 0xbc, 0xc5, 0x67, 0x3a, 0xc8, 0x2a, 0x67, 0x99,
    0xda, 0x3c, 0x14, 0x46, 0x68, 0x2c, 0x25, 0x8c, 0x46, 0x3f, 0xff,
    0xdf, 0x58, 0xdf, 0xd2, 0xfa, 0x3e, 0x6c, 0x37, 0x8b, 0x53, 0xd7,
    0x95, 0xc4, 0xa4, 0xdf, 0xfb, 0x41, 0x99, 0xed, 0xd7, 0x86, 0x2f,
    0x23, 0xab, 0xaf, 0x02, 0x03, 0xb4, 0xb8, 0x91, 0x1b, 0xa0, 0x56,
    0x99, 0x94, 0xe1, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02,
    0x20, 0x60, 0xcd, 0xb6, 0x06, 0x1e, 0x9c, 0x22, 0x26, 0x2d, 0x1a,
    0xac, 0x1d, 0x96, 0xd8, 0xc7, 0x08, 0x29, 0xb2, 0x36, 0x65, 0x31,
    0xdd, 0xa2, 0x68, 0x83, 0x2c, 0xb8, 0x36, 0xbc, 0xd3, 0x0d, 0xfa,
    0x02, 0x20, 0x63, 0x1b, 0x14, 0x59, 0xf0, 0x9e, 0x63, 0x30, 0x05,
    0x57, 0x22, 0xc8, 0xd8, 0x9b, 0x7f, 0x48, 0x88, 0x3b, 0x90, 0x89,
    0xb8, 0x8d, 0x60, 0xd1, 0xd9, 0x79, 0x59, 0x02, 0xb3, 0x04, 0x10,
    0xdf};

static const uint8_t kU2fLabAttestationPrivateKey[32] = {
    0xd1, 0x1c, 0xfc, 0x58, 0xf4, 0x86, 0x34, 0x27, 0xe4, 0x67, 0xe2,
    0x69, 0x24, 0xca, 0xd9, 0xc6, 0x81, 0xb6, 0x5d, 0xd5, 0x57, 0x7e,
    0xfb, 0xda, 0x8d, 0xc0, 0xdb, 0x63, 0xea, 0x16, 0xe0, 0x98};

static const uint8_t kU2fLabAttestationCert[] = {
    0x30, 0x82, 0x01, 0x5d, 0x30, 0x82, 0x01, 0x03, 0xa0, 0x03, 0x02,
    0x01, 0x02, 0x02, 0x14, 0x00, 0xf3, 0x16, 0xcd, 0x9b, 0x4a, 0x69,
    0x32, 0xf0, 0xe9, 0xb4, 0x2e, 0xe5, 0x6e, 0xa3, 0x71, 0x07, 0x2d,
    0x4d, 0x24, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x12, 0x45, 0x53, 0x50, 0x33, 0x32, 0x20,
    0x46, 0x49, 0x44, 0x4f, 0x20, 0x4c, 0x61, 0x62, 0x20, 0x55, 0x32,
    0x46, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x36,
    0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x12, 0x45, 0x53, 0x50, 0x33, 0x32, 0x20, 0x46, 0x49, 0x44,
    0x4f, 0x20, 0x4c, 0x61, 0x62, 0x20, 0x55, 0x32, 0x46, 0x30, 0x59,
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xfe, 0x2e, 0x64, 0xe4, 0x95, 0xeb, 0xae, 0x89,
    0xc0, 0xbb, 0xe7, 0x4d, 0xe4, 0x0d, 0xe1, 0x90, 0xa5, 0xcf, 0xe0,
    0xe0, 0xb7, 0xd5, 0x70, 0x7b, 0xe1, 0x0c, 0x00, 0x6d, 0x6f, 0x95,
    0xfc, 0xc2, 0xa4, 0x9d, 0x24, 0xfa, 0xd5, 0xe6, 0x63, 0x46, 0x10,
    0x5a, 0xe7, 0x5a, 0x8b, 0x23, 0x1e, 0x67, 0xe8, 0xc4, 0x4c, 0xe5,
    0x6d, 0x08, 0xe5, 0xab, 0x27, 0x2d, 0xca, 0x99, 0x0c, 0x69, 0x5f,
    0x93, 0xa3, 0x21, 0x30, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x14, 0xf4, 0x20, 0x75, 0xe3, 0xe4,
    0x07, 0x9d, 0xa2, 0x6b, 0xbb, 0x85, 0x57, 0x12, 0xab, 0x8b, 0xbe,
    0x91, 0x9d, 0xa1, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20,
    0x42, 0x41, 0x45, 0x9c, 0x48, 0x4c, 0x0a, 0x65, 0x0d, 0x92, 0x20,
    0x60, 0x6b, 0xfb, 0x2f, 0x90, 0x64, 0x74, 0xa3, 0x9b, 0xad, 0xea,
    0xd2, 0xc3, 0xbc, 0x1f, 0x21, 0x20, 0x2d, 0xd2, 0xca, 0xbe, 0x02,
    0x21, 0x00, 0xe8, 0x27, 0xd8, 0x19, 0x72, 0x7b, 0xa0, 0x63, 0x1c,
    0x28, 0x38, 0x75, 0xcd, 0x05, 0xbb, 0x21, 0x7e, 0x62, 0xa7, 0x9d,
    0xfe, 0x6d, 0xbd, 0x3e, 0xd8, 0x94, 0xf6, 0x7d, 0x1f, 0xf6, 0xc7,
    0x04};

static bool textEquals(const uint8_t *data, size_t len, const char *text) {
  return strlen(text) == len && memcmp(data, text, len) == 0;
}

static bool isSyntheticRpId(const char *rpId) {
  return rpId && strcmp(rpId, ".dummy") == 0;
}

static void copyBounded(char *out, size_t outSize, const uint8_t *data, size_t len) {
  const size_t copyLen = min(len, outSize - 1);
  memcpy(out, data, copyLen);
  out[copyLen] = 0;
}

Ctap2::Ctap2(CryptoProvider &crypto, CredentialStore &store, UserPresence &presence, AmoledUx &ux,
             LabRecorder &recorder)
    : crypto_(crypto), store_(store), presence_(presence), ux_(ux), recorder_(recorder) {}

void Ctap2::recordEvent(const char *kind, const char *cmd, const char *rp, const char *status, bool synthetic,
                        bool up, bool uv, const char *note, bool proof) {
  LabRecorder::Event event{};
  event.kind = kind;
  event.cmd = cmd;
  event.rp = rp;
  event.status = status;
  event.synthetic = synthetic;
  event.up = up;
  event.uv = uv;
  event.pinSet = pinSet_;
  event.residentCount = store_.residentCount();
  event.credentialCount = store_.count();
  event.note = note;
  event.proof = proof;
  recorder_.record(event);
  syncRecorderUx();
}

void Ctap2::syncRecorderUx() {
  ux_.recorderStatus(recorder_.statusLine(), recorder_.lastSummary());
}

void Ctap2::begin() {
  masterSecret_.begin(crypto_);
  pinPrefs_.begin("fido_pin", false);
  loadPinState();
  pinKeyReady_ = false;
  resetPinToken();
}

void Ctap2::setKeepaliveCallback(KeepaliveCallback callback, void *ctx) {
  keepalive_ = callback;
  keepaliveCtx_ = ctx;
}

void Ctap2::cancel() {
  canceled_ = true;
}

void Ctap2::wipeLabState() {
  store_.wipe();
  clearPinState();
  // Rotate the master secret so every outstanding stateless credential ID is
  // cryptographically invalidated (its MAC and derived key both change).
  masterSecret_.wipe();
}

size_t Ctap2::writeStatus(Ctap2Status status, uint8_t *response, size_t responseCapacity) {
  if (responseCapacity == 0) return 0;
  response[0] = static_cast<uint8_t>(status);
  return 1;
}

size_t Ctap2::handle(const uint8_t *request, size_t requestLen, uint8_t *response, size_t responseCapacity) {
  canceled_ = false;
  if (!request || requestLen == 0) {
    ux_.diagnosticError("CTAP2 error", "Invalid length", "empty request");
    recordEvent("error", "ctap2", "", "invalid-length 0x03", false, false, false, "empty request");
    return writeStatus(Ctap2Status::kInvalidLength, response, responseCapacity);
  }
  switch (request[0]) {
    case kCmdMakeCredential: return handleMakeCredential(request + 1, requestLen - 1, response, responseCapacity);
    case kCmdGetAssertion: return handleGetAssertion(request + 1, requestLen - 1, response, responseCapacity);
    case kCmdGetInfo: return handleGetInfo(response, responseCapacity);
    case kCmdReset: return handleReset(response, responseCapacity);
    case kCmdGetNextAssertion: return handleGetNextAssertion(response, responseCapacity);
    case kCmdCredentialManagement: return handleCredentialManagement(request + 1, requestLen - 1, response, responseCapacity);
    case kCmdClientPin: return handleClientPin(request + 1, requestLen - 1, response, responseCapacity);
    default:
      ux_.diagnosticError("CTAP2 error", "Invalid command", "unsupported CTAP2 cmd");
      recordEvent("error", "ctap2", "", "invalid-command 0x01", false, false, false, "unsupported CTAP2 cmd");
      return writeStatus(Ctap2Status::kInvalidCommand, response, responseCapacity);
  }
}

size_t Ctap2::handleCtap1(const uint8_t *request, size_t requestLen, uint8_t *response, size_t responseCapacity) {
  U2fApdu apdu;
  if (!parseU2fApdu(request, requestLen, apdu)) {
    ux_.diagnosticError("CTAP1", "Wrong length", "APDU parse failed");
    return writeU2fStatus(kU2fSwWrongLength, response, responseCapacity);
  }
  if (apdu.cla != 0) {
    ux_.diagnosticError("CTAP1", "CLA unsupported", "expected 0x00");
    return writeU2fStatus(kU2fSwClaNotSupported, response, responseCapacity);
  }

  switch (apdu.ins) {
    case kU2fVersion:
      return handleU2fVersion(response, responseCapacity);
    case kU2fRegister:
      return handleU2fRegister(apdu, response, responseCapacity);
    case kU2fAuthenticate:
      return handleU2fAuthenticate(apdu, response, responseCapacity);
    default:
      ux_.diagnosticError("CTAP1", "INS unsupported", "not U2F v2");
      return writeU2fStatus(kU2fSwInsNotSupported, response, responseCapacity);
  }
}

bool Ctap2::parseU2fApdu(const uint8_t *request, size_t requestLen, U2fApdu &out) {
  if (!request || requestLen < 4) return false;
  out.cla = request[0];
  out.ins = request[1];
  out.p1 = request[2];
  out.p2 = request[3];
  out.data = nullptr;
  out.dataLen = 0;

  if (requestLen == 4) return true;
  if (requestLen == 5) return true;
  if (request[4] == 0) {
    if (requestLen < 7) return false;
    const size_t lc = (static_cast<size_t>(request[5]) << 8) | request[6];
    if (lc == 0) return true;
    if (requestLen < 7 + lc) return false;
    out.data = request + 7;
    out.dataLen = lc;
    return true;
  }

  const size_t lc = request[4];
  if (requestLen < 5 + lc) return false;
  out.data = request + 5;
  out.dataLen = lc;
  return true;
}

size_t Ctap2::writeU2fStatus(uint16_t status, uint8_t *response, size_t responseCapacity) {
  if (responseCapacity < 2) return 0;
  response[0] = (status >> 8) & 0xff;
  response[1] = status & 0xff;
  return 2;
}

size_t Ctap2::handleU2fVersion(uint8_t *response, size_t responseCapacity) {
  static const char kVersion[] = "U2F_V2";
  if (responseCapacity < sizeof(kVersion) - 1 + 2) return 0;
  memcpy(response, kVersion, sizeof(kVersion) - 1);
  response[sizeof(kVersion) - 1] = 0x90;
  response[sizeof(kVersion)] = 0x00;
  ux_.diagnostic("CTAP1 VERSION", "U2F_V2", "legacy OK");
  return sizeof(kVersion) + 1;
}

size_t Ctap2::handleU2fRegister(const U2fApdu &apdu, uint8_t *response, size_t responseCapacity) {
  if (apdu.dataLen != 64) {
    ux_.diagnosticError("CTAP1 REGISTER", "Wrong length", "expected 64");
    return writeU2fStatus(kU2fSwWrongLength, response, responseCapacity);
  }

  ux_.diagnostic("CTAP1 REGISTER", "Waiting for BOOT", "legacy U2F");
  if (!waitForPresence("REGISTER", "CTAP1/U2F", false)) {
    return writeU2fStatus(kU2fSwConditionsNotSatisfied, response, responseCapacity);
  }

  P256KeyPair key;
  CredentialRecord record{};
  record.magic = kCredentialRecordMagic;
  record.version = kCredentialRecordVersion;
  record.flags = 0;
  if (!crypto_.generateP256(key) || !crypto_.randomBytes(record.credentialId, sizeof(record.credentialId))) {
    ux_.diagnosticError("CTAP1 REGISTER", "Crypto failed", "key or handle");
    return writeU2fStatus(kU2fSwWrongData, response, responseCapacity);
  }

  const uint8_t *challenge = apdu.data;
  const uint8_t *application = apdu.data + 32;
  memcpy(record.rpIdHash, application, 32);
  strlcpy(record.rpId, "u2f", sizeof(record.rpId));
  strlcpy(record.rpName, "U2F", sizeof(record.rpName));
  memcpy(record.userHandle, "u2f", 3);
  record.userHandleLen = 3;
  strlcpy(record.userName, "u2f", sizeof(record.userName));
  strlcpy(record.userDisplayName, "u2f", sizeof(record.userDisplayName));
  memcpy(record.privateKey, key.privateKey, 32);
  memcpy(record.publicX, key.publicX, 32);
  memcpy(record.publicY, key.publicY, 32);
  record.signCount = 1;

  if (!store_.add(record)) {
    ux_.diagnosticError("CTAP1 REGISTER", "Store failed", "NVS add failed");
    return writeU2fStatus(kU2fSwWrongData, response, responseCapacity);
  }

  uint8_t publicKey[65];
  publicKey[0] = 0x04;
  memcpy(publicKey + 1, key.publicX, 32);
  memcpy(publicKey + 33, key.publicY, 32);

  uint8_t signatureBase[1 + 32 + 32 + 32 + 65];
  size_t baseOffset = 0;
  signatureBase[baseOffset++] = 0x00;
  memcpy(signatureBase + baseOffset, application, 32);
  baseOffset += 32;
  memcpy(signatureBase + baseOffset, challenge, 32);
  baseOffset += 32;
  memcpy(signatureBase + baseOffset, record.credentialId, 32);
  baseOffset += 32;
  memcpy(signatureBase + baseOffset, publicKey, sizeof(publicKey));
  baseOffset += sizeof(publicKey);

  uint8_t hash[32];
  uint8_t signature[96];
  size_t signatureLen = 0;
  if (!crypto_.sha256(signatureBase, baseOffset, hash) ||
      !crypto_.signP256Der(kU2fLabAttestationPrivateKey, hash, signature, sizeof(signature), signatureLen)) {
    ux_.diagnosticError("CTAP1 REGISTER", "Attest failed", "signature failed");
    return writeU2fStatus(kU2fSwWrongData, response, responseCapacity);
  }

  const size_t needed = 1 + sizeof(publicKey) + 1 + 32 + sizeof(kU2fLabAttestationCert) + signatureLen + 2;
  if (responseCapacity < needed) return writeU2fStatus(kU2fSwWrongLength, response, responseCapacity);
  size_t offset = 0;
  response[offset++] = 0x05;
  memcpy(response + offset, publicKey, sizeof(publicKey));
  offset += sizeof(publicKey);
  response[offset++] = 32;
  memcpy(response + offset, record.credentialId, 32);
  offset += 32;
  memcpy(response + offset, kU2fLabAttestationCert, sizeof(kU2fLabAttestationCert));
  offset += sizeof(kU2fLabAttestationCert);
  memcpy(response + offset, signature, signatureLen);
  offset += signatureLen;
  response[offset++] = 0x90;
  response[offset++] = 0x00;
  recordEvent("proof", "u2fRegister", "", "ok 0x9000", false, true, false, "legacy U2F register", true);
  ux_.success("U2F Registered");
  return offset;
}

size_t Ctap2::handleU2fAuthenticate(const U2fApdu &apdu, uint8_t *response, size_t responseCapacity) {
  if (apdu.dataLen < 65) {
    ux_.diagnosticError("CTAP1 AUTH", "Wrong length", "too short");
    return writeU2fStatus(kU2fSwWrongLength, response, responseCapacity);
  }

  const uint8_t *challenge = apdu.data;
  const uint8_t *application = apdu.data + 32;
  const uint8_t keyHandleLen = apdu.data[64];
  if (apdu.dataLen != 65 + keyHandleLen) {
    ux_.diagnosticError("CTAP1 AUTH", "Wrong length", "bad handle len");
    return writeU2fStatus(kU2fSwWrongLength, response, responseCapacity);
  }

  CredentialRecord record;
  size_t recordIndex = 0;
  const uint8_t *keyHandle = apdu.data + 65;
  if (!store_.findByCredentialId(keyHandle, keyHandleLen, record, &recordIndex) ||
      memcmp(record.rpIdHash, application, 32) != 0) {
    ux_.diagnosticError("CTAP1 AUTH", "Bad key handle", "not found");
    return writeU2fStatus(kU2fSwWrongData, response, responseCapacity);
  }

  if (apdu.p1 == 0x07) {
    ux_.diagnostic("CTAP1 AUTH", "Check-only match", "presence required");
    return writeU2fStatus(kU2fSwConditionsNotSatisfied, response, responseCapacity);
  }
  if (apdu.p1 != 0x03 && apdu.p1 != 0x08) {
    ux_.diagnosticError("CTAP1 AUTH", "Bad control byte", "unsupported P1");
    return writeU2fStatus(kU2fSwWrongData, response, responseCapacity);
  }
  if (apdu.p1 == 0x03) {
    ux_.diagnostic("CTAP1 AUTH", "Waiting for BOOT", "legacy U2F");
    if (!waitForPresence("LOGIN", "CTAP1/U2F", false)) {
      return writeU2fStatus(kU2fSwConditionsNotSatisfied, response, responseCapacity);
    }
  }

  record.signCount++;
  const uint8_t up = 0x01;
  uint8_t signatureBase[32 + 1 + 4 + 32];
  size_t offset = 0;
  memcpy(signatureBase + offset, application, 32);
  offset += 32;
  signatureBase[offset++] = up;
  signatureBase[offset++] = (record.signCount >> 24) & 0xff;
  signatureBase[offset++] = (record.signCount >> 16) & 0xff;
  signatureBase[offset++] = (record.signCount >> 8) & 0xff;
  signatureBase[offset++] = record.signCount & 0xff;
  memcpy(signatureBase + offset, challenge, 32);
  offset += 32;

  uint8_t hash[32];
  uint8_t signature[96];
  size_t signatureLen = 0;
  if (!crypto_.sha256(signatureBase, offset, hash) ||
      !crypto_.signP256Der(record.privateKey, hash, signature, sizeof(signature), signatureLen)) {
    ux_.diagnosticError("CTAP1 AUTH", "Crypto failed", "sign failed");
    return writeU2fStatus(kU2fSwWrongData, response, responseCapacity);
  }
  store_.updateCounter(recordIndex, record.signCount);

  const size_t needed = 1 + 4 + signatureLen + 2;
  if (responseCapacity < needed) return writeU2fStatus(kU2fSwWrongLength, response, responseCapacity);
  offset = 0;
  response[offset++] = up;
  response[offset++] = (record.signCount >> 24) & 0xff;
  response[offset++] = (record.signCount >> 16) & 0xff;
  response[offset++] = (record.signCount >> 8) & 0xff;
  response[offset++] = record.signCount & 0xff;
  memcpy(response + offset, signature, signatureLen);
  offset += signatureLen;
  response[offset++] = 0x90;
  response[offset++] = 0x00;
  recordEvent("proof", "u2fAuthenticate", "", "ok 0x9000", false, true, false, "legacy U2F sign", true);
  ux_.success("U2F Signed");
  return offset;
}

size_t Ctap2::handleGetInfo(uint8_t *response, size_t responseCapacity) {
  if (responseCapacity < 2) return 0;
  response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
  CborWriter writer(response + 1, responseCapacity - 1);

  static const uint8_t aaguid[16] = {
      0x45, 0x53, 0x50, 0x33, 0x32, 0x53, 0x33, 0x4b, 0x45, 0x59, 0x4c, 0x41, 0x42, 0x00, 0x00, 0x01};

  writer.writeMap(7);
  writer.writeUInt(1);
  writer.writeArray(1);
  writer.writeText("FIDO_2_0");
  writer.writeUInt(3);
  writer.writeBytes(aaguid, sizeof(aaguid));
  writer.writeUInt(4);
  writer.writeMap(6);
  writer.writeText("rk");
  writer.writeBool(true);
  writer.writeText("up");
  writer.writeBool(true);
  writer.writeText("uv");
  writer.writeBool(false);
  writer.writeText("plat");
  writer.writeBool(false);
  writer.writeText("clientPin");
  writer.writeBool(pinSet_);
  writer.writeText("pinUvAuthToken");
  writer.writeBool(true);
  writer.writeUInt(5);
  writer.writeUInt(BuildConfig::kMaxCtapMessageSize);
  writer.writeUInt(6);
  writer.writeArray(1);
  writer.writeUInt(kPinProtocolTwo);
  writer.writeUInt(9);
  writer.writeArray(1);
  writer.writeText("usb");
  writer.writeUInt(10);
  writer.writeArray(1);
  writer.writeMap(2);
  writer.writeText("alg");
  writer.writeInt(-7);
  writer.writeText("type");
  writer.writeText("public-key");

  if (!writer.ok()) {
    ux_.diagnosticError("getInfo", "Encode failed", "CTAP2 other");
    recordEvent("error", "getInfo", "", "other 0x7f", false, false, false, "CBOR encode failed");
    return writeStatus(Ctap2Status::kOther, response, responseCapacity);
  }
  recordEvent("trace", "getInfo", "", "ok 0x00", false, false, false, "browser probe");
  return 1 + writer.size();
}

bool Ctap2::parseRpMap(CborReader &reader, MakeCredentialRequest &out) {
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t *key;
    size_t keyLen;
    if (!reader.readTextView(key, keyLen)) return false;
    if (textEquals(key, keyLen, "id")) {
      const uint8_t *rp;
      size_t rpLen;
      if (!reader.readTextView(rp, rpLen) || rpLen == 0 || rpLen >= sizeof(out.rpId)) return false;
      copyBounded(out.rpId, sizeof(out.rpId), rp, rpLen);
      out.hasRpId = crypto_.sha256(rp, rpLen, out.rpIdHash);
      if (!out.hasRpId) return false;
    } else if (textEquals(key, keyLen, "name")) {
      const uint8_t *name;
      size_t nameLen;
      if (!reader.readTextView(name, nameLen)) return false;
      copyBounded(out.rpName, sizeof(out.rpName), name, nameLen);
    } else {
      if (!reader.skip()) return false;
    }
  }
  return out.hasRpId;
}

bool Ctap2::parseUserMap(CborReader &reader, MakeCredentialRequest &out) {
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t *key;
    size_t keyLen;
    if (!reader.readTextView(key, keyLen)) return false;
    if (textEquals(key, keyLen, "id")) {
      const uint8_t *id;
      size_t idLen;
      if (!reader.readBytes(id, idLen) || idLen == 0 || idLen > sizeof(out.userHandle)) return false;
      memcpy(out.userHandle, id, idLen);
      out.userHandleLen = idLen;
      out.hasUser = true;
    } else if (textEquals(key, keyLen, "name")) {
      const uint8_t *name;
      size_t nameLen;
      if (!reader.readTextView(name, nameLen)) return false;
      copyBounded(out.userName, sizeof(out.userName), name, nameLen);
    } else if (textEquals(key, keyLen, "displayName")) {
      const uint8_t *name;
      size_t nameLen;
      if (!reader.readTextView(name, nameLen)) return false;
      copyBounded(out.userDisplayName, sizeof(out.userDisplayName), name, nameLen);
    } else {
      if (!reader.skip()) return false;
    }
  }
  return out.hasUser;
}

bool Ctap2::parsePubKeyCredParams(CborReader &reader, MakeCredentialRequest &out) {
  size_t arrayCount;
  if (!reader.readArray(arrayCount)) return false;
  for (size_t i = 0; i < arrayCount; ++i) {
    size_t mapCount;
    if (!reader.readMap(mapCount)) return false;
    for (size_t j = 0; j < mapCount; ++j) {
      const uint8_t *key;
      size_t keyLen;
      if (!reader.readTextView(key, keyLen)) return false;
      if (textEquals(key, keyLen, "alg")) {
        int64_t alg;
        if (!reader.readInt(alg)) return false;
        if (alg == -7) out.supportsEs256 = true;
      } else {
        if (!reader.skip()) return false;
      }
    }
  }
  return true;
}

bool Ctap2::parseOptions(CborReader &reader, bool &rk, bool &uv, bool *up) {
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t *key;
    size_t keyLen;
    bool value;
    if (!reader.readTextView(key, keyLen) || !reader.readBool(value)) return false;
    if (textEquals(key, keyLen, "rk")) rk = value;
    if (textEquals(key, keyLen, "uv")) uv = value;
    if (up && textEquals(key, keyLen, "up")) *up = value;
  }
  return true;
}

bool Ctap2::parseCredentialDescriptor(CborReader &reader, const uint8_t *&id, size_t &idLen) {
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t *key;
    size_t keyLen;
    if (!reader.readTextView(key, keyLen)) return false;
    if (textEquals(key, keyLen, "id")) {
      if (!reader.readBytes(id, idLen)) return false;
    } else {
      if (!reader.skip()) return false;
    }
  }
  return id && idLen > 0;
}

bool Ctap2::parseMakeCredential(const uint8_t *payload, size_t len, MakeCredentialRequest &out) {
  CborReader reader(payload, len);
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    int64_t key;
    if (!reader.readInt(key)) return false;
    switch (key) {
      case 1: {
        const uint8_t *hash;
        size_t hashLen;
        if (!reader.readBytes(hash, hashLen) || hashLen != 32) return false;
        memcpy(out.clientDataHash, hash, 32);
        out.hasClientDataHash = true;
        break;
      }
      case 2:
        if (!parseRpMap(reader, out)) return false;
        break;
      case 3:
        if (!parseUserMap(reader, out)) return false;
        break;
      case 4:
        if (!parsePubKeyCredParams(reader, out)) return false;
        break;
      case 5: {
        size_t arrayCount;
        if (!reader.readArray(arrayCount)) return false;
        if (arrayCount > 0) {
          if (!parseCredentialDescriptor(reader, out.excludeCredentialId, out.excludeCredentialIdLen)) return false;
          for (size_t n = 1; n < arrayCount; ++n) {
            if (!reader.skip()) return false;
          }
        }
        break;
      }
      case 7:
        if (!parseOptions(reader, out.requireResidentKey, out.requireUserVerification)) return false;
        break;
      case 8: {
        const uint8_t *param;
        size_t paramLen;
        if (!reader.readBytes(param, paramLen)) return false;
        out.pinUvAuthParam = param;
        out.pinUvAuthParamLen = paramLen;
        out.hasPinUvAuthParam = true;
        break;
      }
      case 9: {
        uint64_t protocol;
        if (!reader.readUInt(protocol) || protocol > 0xff) return false;
        out.pinUvAuthProtocol = static_cast<uint8_t>(protocol);
        break;
      }
      default:
        if (!reader.skip()) return false;
        break;
    }
  }
  return out.hasClientDataHash && out.hasRpId && out.hasUser && out.supportsEs256;
}

bool Ctap2::parseGetAssertion(const uint8_t *payload, size_t len, GetAssertionRequest &out) {
  CborReader reader(payload, len);
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    int64_t key;
    if (!reader.readInt(key)) return false;
    switch (key) {
      case 1: {
        const uint8_t *rp;
        size_t rpLen;
        if (!reader.readTextView(rp, rpLen) || rpLen == 0 || rpLen >= sizeof(out.rpId)) return false;
        copyBounded(out.rpId, sizeof(out.rpId), rp, rpLen);
        out.hasRpId = crypto_.sha256(rp, rpLen, out.rpIdHash);
        break;
      }
      case 2: {
        const uint8_t *hash;
        size_t hashLen;
        if (!reader.readBytes(hash, hashLen) || hashLen != 32) return false;
        memcpy(out.clientDataHash, hash, 32);
        out.hasClientDataHash = true;
        break;
      }
      case 3: {
        size_t arrayCount;
        if (!reader.readArray(arrayCount)) return false;
        // Capture every allowList descriptor (real browsers send more than one
        // for multi-account RPs). Entries beyond the cap are still consumed.
        for (size_t n = 0; n < arrayCount; ++n) {
          const uint8_t *id = nullptr;
          size_t idLen = 0;
          if (!parseCredentialDescriptor(reader, id, idLen)) return false;
          if (out.allowListCount < kMaxAllowListEntries) {
            out.allowList[out.allowListCount].id = id;
            out.allowList[out.allowListCount].idLen = idLen;
            out.allowListCount++;
          }
        }
        out.hasAllowList = out.allowListCount > 0;
        break;
      }
      case 5: {
        bool rk = false;
        if (!parseOptions(reader, rk, out.requireUserVerification, &out.userPresenceRequested)) return false;
        break;
      }
      case 6: {
        const uint8_t *param;
        size_t paramLen;
        if (!reader.readBytes(param, paramLen)) return false;
        out.pinUvAuthParam = param;
        out.pinUvAuthParamLen = paramLen;
        out.hasPinUvAuthParam = true;
        break;
      }
      case 7: {
        uint64_t protocol;
        if (!reader.readUInt(protocol) || protocol > 0xff) return false;
        out.pinUvAuthProtocol = static_cast<uint8_t>(protocol);
        break;
      }
      default:
        if (!reader.skip()) return false;
        break;
    }
  }
  return out.hasRpId && out.hasClientDataHash;
}

bool Ctap2::parseCredentialManagementUser(CborReader &reader, CredentialManagementRequest &out) {
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t *key;
    size_t keyLen;
    if (!reader.readTextView(key, keyLen)) return false;
    if (textEquals(key, keyLen, "id")) {
      const uint8_t *id;
      size_t idLen;
      if (!reader.readBytes(id, idLen) || idLen == 0 || idLen > sizeof(out.userHandle)) return false;
      memcpy(out.userHandle, id, idLen);
      out.userHandleLen = idLen;
      out.hasUser = true;
    } else if (textEquals(key, keyLen, "name")) {
      const uint8_t *name;
      size_t nameLen;
      if (!reader.readTextView(name, nameLen)) return false;
      copyBounded(out.userName, sizeof(out.userName), name, nameLen);
    } else if (textEquals(key, keyLen, "displayName")) {
      const uint8_t *name;
      size_t nameLen;
      if (!reader.readTextView(name, nameLen)) return false;
      copyBounded(out.userDisplayName, sizeof(out.userDisplayName), name, nameLen);
    } else {
      if (!reader.skip()) return false;
    }
  }
  return out.hasUser;
}

bool Ctap2::parseCredentialManagementParams(CborReader &reader, CredentialManagementRequest &out) {
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    int64_t key;
    if (!reader.readInt(key)) return false;
    switch (key) {
      case 1: {
        const uint8_t *hash;
        size_t hashLen;
        if (!reader.readBytes(hash, hashLen) || hashLen != 32) return false;
        memcpy(out.rpIdHash, hash, 32);
        out.hasRpIdHash = true;
        break;
      }
      case 2:
        if (!parseCredentialDescriptor(reader, out.credentialId, out.credentialIdLen)) return false;
        out.hasCredentialId = true;
        break;
      case 3:
        if (!parseCredentialManagementUser(reader, out)) return false;
        break;
      default:
        if (!reader.skip()) return false;
        break;
    }
  }
  return true;
}

bool Ctap2::parseCredentialManagement(const uint8_t *payload, size_t len, CredentialManagementRequest &out) {
  CborReader reader(payload, len);
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    int64_t key;
    if (!reader.readInt(key)) return false;
    switch (key) {
      case 1: {
        uint64_t subCommand;
        if (!reader.readUInt(subCommand) || subCommand > 0xff) return false;
        out.subCommand = static_cast<uint8_t>(subCommand);
        break;
      }
      case 2:
        if (!parseCredentialManagementParams(reader, out)) return false;
        break;
      default:
        if (!reader.skip()) return false;
        break;
    }
  }
  return out.subCommand != 0;
}

bool Ctap2::waitForPresence(const char *action, const char *rpId, bool sendKeepalive) {
  ux_.waitingForPresence(action, rpId);
  const uint32_t started = millis();
  uint32_t lastKeepalive = 0;
  while (millis() - started < BuildConfig::kUserPresenceTimeoutMs) {
    if (canceled_) {
      ux_.diagnosticError(action, "Canceled by host", "browser stopped");
      recordEvent("cancel", action, rpId, "canceled 0x2d", false, false, false, "host canceled wait");
      return false;
    }
    if (presence_.isPressed()) {
      delay(25);
      const bool confirmed = presence_.isPressed();
      if (confirmed) {
        ux_.diagnostic("BOOT detected", action, rpId);
      }
      return confirmed;
    }
    if (sendKeepalive && keepalive_ && millis() - lastKeepalive >= 1000) {
      keepalive_(keepaliveCtx_, 0x02);
      lastKeepalive = millis();
    }
    delay(5);
  }
  ux_.diagnosticError(action, "Timeout", "BOOT not detected");
  recordEvent("timeout", action, rpId, "timeout 0x2f", false, false, false, "BOOT not detected");
  return false;
}

bool Ctap2::writeCoseKey(CborWriter &writer, const uint8_t x[32], const uint8_t y[32]) {
  writer.writeMap(5);
  writer.writeInt(1);
  writer.writeInt(2);
  writer.writeInt(3);
  writer.writeInt(-7);
  writer.writeInt(-1);
  writer.writeInt(1);
  writer.writeInt(-2);
  writer.writeBytes(x, 32);
  writer.writeInt(-3);
  writer.writeBytes(y, 32);
  return writer.ok();
}

bool Ctap2::writeKeyAgreement(CborWriter &writer) {
  if (!pinKeyReady_) {
    pinKeyReady_ = crypto_.generateP256(pinKeyAgreement_);
  }
  if (!pinKeyReady_) return false;
  writer.writeMap(5);
  writer.writeInt(1);
  writer.writeInt(2);
  writer.writeInt(3);
  writer.writeInt(-25);
  writer.writeInt(-1);
  writer.writeInt(1);
  writer.writeInt(-2);
  writer.writeBytes(pinKeyAgreement_.publicX, 32);
  writer.writeInt(-3);
  writer.writeBytes(pinKeyAgreement_.publicY, 32);
  return writer.ok();
}

bool Ctap2::parseCoseP256(CborReader &reader, uint8_t x[32], uint8_t y[32]) {
  size_t count;
  if (!reader.readMap(count)) return false;
  bool hasX = false;
  bool hasY = false;
  for (size_t i = 0; i < count; ++i) {
    int64_t key;
    if (!reader.readInt(key)) return false;
    if (key == -2 || key == -3) {
      const uint8_t *data;
      size_t len;
      if (!reader.readBytes(data, len) || len != 32) return false;
      memcpy(key == -2 ? x : y, data, 32);
      if (key == -2) hasX = true;
      if (key == -3) hasY = true;
    } else {
      if (!reader.skip()) return false;
    }
  }
  return hasX && hasY;
}

bool Ctap2::parseClientPin(const uint8_t *payload, size_t len, ClientPinRequest &out) {
  CborReader reader(payload, len);
  size_t count;
  if (!reader.readMap(count)) return false;
  for (size_t i = 0; i < count; ++i) {
    int64_t key;
    if (!reader.readInt(key)) return false;
    switch (key) {
      case 1: {
        uint64_t protocol;
        if (!reader.readUInt(protocol) || protocol > 0xff) return false;
        out.pinUvAuthProtocol = static_cast<uint8_t>(protocol);
        break;
      }
      case 2: {
        uint64_t subCommand;
        if (!reader.readUInt(subCommand) || subCommand > 0xff) return false;
        out.subCommand = static_cast<uint8_t>(subCommand);
        break;
      }
      case 3:
        if (!parseCoseP256(reader, out.peerX, out.peerY)) return false;
        out.hasKeyAgreement = true;
        break;
      case 4:
        if (!reader.readBytes(out.pinUvAuthParam, out.pinUvAuthParamLen)) return false;
        break;
      case 5:
        if (!reader.readBytes(out.newPinEnc, out.newPinEncLen)) return false;
        break;
      case 6:
        if (!reader.readBytes(out.pinHashEnc, out.pinHashEncLen)) return false;
        break;
      case 9: {
        uint64_t permissions;
        if (!reader.readUInt(permissions) || permissions > 0xffffffffULL) return false;
        out.permissions = static_cast<uint32_t>(permissions);
        out.hasPermissions = true;
        break;
      }
      case 10: {
        const uint8_t *rp;
        size_t rpLen;
        if (!reader.readTextView(rp, rpLen) || rpLen >= sizeof(out.rpId)) return false;
        copyBounded(out.rpId, sizeof(out.rpId), rp, rpLen);
        break;
      }
      default:
        if (!reader.skip()) return false;
        break;
    }
  }
  return out.subCommand != 0;
}

bool Ctap2::derivePinSharedSecret(const ClientPinRequest &req, uint8_t sharedSecret[64]) {
  if (req.pinUvAuthProtocol != kPinProtocolTwo || !req.hasKeyAgreement) return false;
  if (!pinKeyReady_) {
    pinKeyReady_ = crypto_.generateP256(pinKeyAgreement_);
  }
  if (!pinKeyReady_) return false;
  uint8_t z[32];
  uint8_t hmacKey[32];
  uint8_t aesKey[32];
  static const uint8_t kHmacInfo[] = "CTAP2 HMAC key";
  static const uint8_t kAesInfo[] = "CTAP2 AES key";
  const bool ok = crypto_.ecdhP256(pinKeyAgreement_.privateKey, req.peerX, req.peerY, z) &&
                  crypto_.hkdfSha256(z, sizeof(z), kHmacInfo, sizeof(kHmacInfo) - 1, hmacKey) &&
                  crypto_.hkdfSha256(z, sizeof(z), kAesInfo, sizeof(kAesInfo) - 1, aesKey);
  if (ok) {
    memcpy(sharedSecret, hmacKey, 32);
    memcpy(sharedSecret + 32, aesKey, 32);
  }
  memset(z, 0, sizeof(z));
  memset(hmacKey, 0, sizeof(hmacKey));
  memset(aesKey, 0, sizeof(aesKey));
  return ok;
}

bool Ctap2::clientPinDecrypt(const uint8_t sharedSecret[64], const uint8_t *cipher, size_t cipherLen, uint8_t *plain,
                             size_t plainCapacity, size_t &plainLen) {
  plainLen = 0;
  if (!cipher || !plain || cipherLen < 32 || ((cipherLen - 16) % 16) != 0 || cipherLen - 16 > plainCapacity) {
    return false;
  }
  if (!crypto_.aes256CbcDecrypt(sharedSecret + 32, cipher, cipher + 16, cipherLen - 16, plain)) return false;
  plainLen = cipherLen - 16;
  return true;
}

bool Ctap2::clientPinEncrypt(const uint8_t sharedSecret[64], const uint8_t *plain, size_t plainLen, uint8_t *cipher,
                             size_t cipherCapacity, size_t &cipherLen) {
  cipherLen = 0;
  if (!plain || !cipher || plainLen == 0 || (plainLen % 16) != 0 || cipherCapacity < plainLen + 16) return false;
  if (!crypto_.randomBytes(cipher, 16)) return false;
  if (!crypto_.aes256CbcEncrypt(sharedSecret + 32, cipher, plain, plainLen, cipher + 16)) return false;
  cipherLen = plainLen + 16;
  return true;
}

bool Ctap2::clientPinVerify(const uint8_t *key, size_t keyLen, const uint8_t *message, size_t messageLen,
                            const uint8_t *signature, size_t signatureLen) {
  if (!key || !message || !signature || signatureLen != 32) return false;
  uint8_t expected[32];
  const bool ok = crypto_.hmacSha256(key, keyLen, message, messageLen, expected) &&
                  memcmp(expected, signature, 32) == 0;
  memset(expected, 0, sizeof(expected));
  return ok;
}

void Ctap2::resetPinToken() {
  crypto_.randomBytes(pinUvAuthToken_, sizeof(pinUvAuthToken_));
  pinTokenPermissions_ = 0;
  pinTokenRpId_[0] = 0;
  pinTokenInUse_ = false;
}

void Ctap2::loadPinState() {
  pinSet_ = pinPrefs_.getBool("set", false);
  pinRetries_ = pinPrefs_.getUChar("retries", kPinMaxRetries);
  if (pinRetries_ > kPinMaxRetries) pinRetries_ = kPinMaxRetries;
  if (pinSet_ && pinPrefs_.getBytesLength("hash") == sizeof(storedPinHash_)) {
    pinPrefs_.getBytes("hash", storedPinHash_, sizeof(storedPinHash_));
  } else {
    pinSet_ = false;
    memset(storedPinHash_, 0, sizeof(storedPinHash_));
    pinRetries_ = kPinMaxRetries;
  }
}

void Ctap2::savePinState() {
  pinPrefs_.putBool("set", pinSet_);
  pinPrefs_.putUChar("retries", pinRetries_);
  if (pinSet_) {
    pinPrefs_.putBytes("hash", storedPinHash_, sizeof(storedPinHash_));
  } else {
    pinPrefs_.remove("hash");
  }
}

void Ctap2::clearPinState() {
  pinSet_ = false;
  pinRetries_ = kPinMaxRetries;
  pinMismatches_ = 0;
  memset(storedPinHash_, 0, sizeof(storedPinHash_));
  savePinState();
  resetPinToken();
}

bool Ctap2::verifyPinUvAuthParam(uint8_t protocol, const uint8_t *message, size_t messageLen,
                                 const uint8_t *signature, size_t signatureLen, uint8_t permission,
                                 const char *rpId) {
  if (protocol != kPinProtocolTwo || !pinTokenInUse_) return false;
  if ((pinTokenPermissions_ & permission) == 0) return false;
  if (pinTokenRpId_[0] && rpId && strcmp(pinTokenRpId_, rpId) != 0) return false;
  return clientPinVerify(pinUvAuthToken_, sizeof(pinUvAuthToken_), message, messageLen, signature, signatureLen);
}

bool Ctap2::buildAuthData(const uint8_t rpIdHash[32], uint8_t flags, uint32_t signCount, const uint8_t *attestedCredId,
                          size_t attestedCredIdLen, const uint8_t *attestedPubX, const uint8_t *attestedPubY,
                          uint8_t *out, size_t outCapacity, size_t &outLen) {
  outLen = 0;
  if (outCapacity < 37) return false;
  memcpy(out, rpIdHash, 32);
  out[32] = flags;
  out[33] = (signCount >> 24) & 0xff;
  out[34] = (signCount >> 16) & 0xff;
  out[35] = (signCount >> 8) & 0xff;
  out[36] = signCount & 0xff;
  outLen = 37;

  if (!attestedCredId) return true;
  static const uint8_t aaguid[16] = {
      0x45, 0x53, 0x50, 0x33, 0x32, 0x53, 0x33, 0x4b, 0x45, 0x59, 0x4c, 0x41, 0x42, 0x00, 0x00, 0x01};
  // Credential ID length is a variable 2-byte big-endian field: 32 for resident/
  // legacy records, kStatelessCredIdLen (33) for key-wrapped non-resident creds.
  if (attestedCredIdLen == 0 || attestedCredIdLen > 0xffff) return false;
  if (outCapacity < outLen + sizeof(aaguid) + 2 + attestedCredIdLen + 128) return false;
  memcpy(out + outLen, aaguid, sizeof(aaguid));
  outLen += sizeof(aaguid);
  out[outLen++] = (attestedCredIdLen >> 8) & 0xff;
  out[outLen++] = attestedCredIdLen & 0xff;
  memcpy(out + outLen, attestedCredId, attestedCredIdLen);
  outLen += attestedCredIdLen;
  CborWriter cose(out + outLen, outCapacity - outLen);
  if (!writeCoseKey(cose, attestedPubX, attestedPubY)) return false;
  outLen += cose.size();
  return true;
}

// ---- Stateless credential key-wrapping (Phase 1) ----
//
// Non-resident credentials store nothing on the device. The credential ID is
// [version:1][nonce:16][MAC:16]; the P-256 private key is re-derived on demand
// from (deviceSeedKey, nonce, rpIdHash), and the MAC (over version||nonce||
// rpIdHash, keyed by deviceMacKey) authenticates the ID and binds it to one RP.

bool Ctap2::deriveStatelessKeyFromNonce(const uint8_t *nonce, const uint8_t rpIdHash[32], P256KeyPair &outKey) {
  uint8_t seedKey[32];
  if (!masterSecret_.deriveSeedKey(seedKey)) return false;
  uint8_t seedInput[1 + kStatelessNonceLen + 32];
  seedInput[0] = kStatelessCredIdVersion;
  memcpy(seedInput + 1, nonce, kStatelessNonceLen);
  memcpy(seedInput + 1 + kStatelessNonceLen, rpIdHash, 32);
  uint8_t seed[32];
  const bool ok = crypto_.hkdfSha256(seedKey, sizeof(seedKey), seedInput, sizeof(seedInput), seed) &&
                  crypto_.deriveP256FromSeed(seed, outKey);
  memset(seedKey, 0, sizeof(seedKey));
  memset(seed, 0, sizeof(seed));
  return ok;
}

bool Ctap2::computeStatelessMac(const uint8_t *nonce, const uint8_t rpIdHash[32], uint8_t macOut[16]) {
  uint8_t macKey[32];
  if (!masterSecret_.deriveMacKey(macKey)) return false;
  uint8_t input[1 + kStatelessNonceLen + 32];
  input[0] = kStatelessCredIdVersion;
  memcpy(input + 1, nonce, kStatelessNonceLen);
  memcpy(input + 1 + kStatelessNonceLen, rpIdHash, 32);
  uint8_t full[32];
  const bool ok = crypto_.hmacSha256(macKey, sizeof(macKey), input, sizeof(input), full);
  if (ok) memcpy(macOut, full, kStatelessMacLen);
  memset(macKey, 0, sizeof(macKey));
  memset(full, 0, sizeof(full));
  return ok;
}

bool Ctap2::buildStatelessCredentialId(const uint8_t rpIdHash[32], uint8_t outId[33], P256KeyPair &outKey) {
  // deriveP256FromSeed rejects the (astronomically unlikely) d==0 case; draw a
  // fresh nonce and retry so a successfully issued ID always re-derives at login.
  for (int attempt = 0; attempt < 8; ++attempt) {
    uint8_t nonce[kStatelessNonceLen];
    if (!crypto_.randomBytes(nonce, sizeof(nonce))) return false;
    if (!deriveStatelessKeyFromNonce(nonce, rpIdHash, outKey)) continue;
    uint8_t mac[kStatelessMacLen];
    if (!computeStatelessMac(nonce, rpIdHash, mac)) return false;
    outId[0] = kStatelessCredIdVersion;
    memcpy(outId + 1, nonce, kStatelessNonceLen);
    memcpy(outId + 1 + kStatelessNonceLen, mac, kStatelessMacLen);
    return true;
  }
  return false;
}

bool Ctap2::isStatelessCredentialId(const uint8_t *id, size_t len, const uint8_t rpIdHash[32]) {
  if (!id || len != kStatelessCredIdLen || id[0] != kStatelessCredIdVersion) return false;
  uint8_t mac[kStatelessMacLen];
  if (!computeStatelessMac(id + 1, rpIdHash, mac)) return false;
  // Constant-time compare to avoid a timing oracle on the credential-ID MAC.
  uint8_t diff = 0;
  for (size_t i = 0; i < kStatelessMacLen; ++i) diff |= mac[i] ^ id[1 + kStatelessNonceLen + i];
  memset(mac, 0, sizeof(mac));
  return diff == 0;
}

bool Ctap2::deriveStatelessKey(const uint8_t *id, const uint8_t rpIdHash[32], P256KeyPair &outKey) {
  return deriveStatelessKeyFromNonce(id + 1, rpIdHash, outKey);
}

size_t Ctap2::handleClientPin(const uint8_t *payload, size_t len, uint8_t *response, size_t responseCapacity) {
  ClientPinRequest req{};
  if (!parseClientPin(payload, len, req)) {
    ux_.diagnosticError("clientPin", "Invalid CBOR", "parse failed");
    recordEvent("error", "clientPin", "", "invalid-cbor 0x12", false, false, false, "parse failed");
    return writeStatus(Ctap2Status::kInvalidCbor, response, responseCapacity);
  }
  if (req.pinUvAuthProtocol != kPinProtocolTwo) {
    ux_.diagnosticError("clientPin", "Bad protocol", "need PIN protocol 2");
    recordEvent("error", "clientPin", req.rpId, "invalid-parameter 0x02", false, false, false,
                "bad PIN protocol");
    return writeStatus(Ctap2Status::kInvalidParameter, response, responseCapacity);
  }

  switch (req.subCommand) {
    case kClientPinGetRetries: {
      response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
      CborWriter writer(response + 1, responseCapacity - 1);
      writer.writeMap(1);
      writer.writeUInt(3);
      writer.writeUInt(pinRetries_);
      ux_.diagnostic("clientPin", "Retries", pinSet_ ? "PIN set" : "PIN not set");
      recordEvent("trace", "clientPin", "", "ok 0x00", false, false, false, "get retries");
      return writer.ok() ? 1 + writer.size() : writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }

    case kClientPinGetKeyAgreement: {
      response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
      CborWriter writer(response + 1, responseCapacity - 1);
      writer.writeMap(1);
      writer.writeUInt(1);
      if (!writeKeyAgreement(writer)) return writeStatus(Ctap2Status::kOther, response, responseCapacity);
      ux_.diagnostic("clientPin", "Key agreement", "protocol 2");
      recordEvent("trace", "clientPin", "", "ok 0x00", false, false, false, "key agreement");
      return writer.ok() ? 1 + writer.size() : writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }

    case kClientPinSetPin:
    case kClientPinChangePin: {
      if (!req.hasKeyAgreement || !req.newPinEnc || !req.pinUvAuthParam || req.pinUvAuthParamLen != 32) {
        return writeStatus(Ctap2Status::kMissingParameter, response, responseCapacity);
      }
      if (req.subCommand == kClientPinSetPin && pinSet_) {
        return writeStatus(Ctap2Status::kPinAuthInvalid, response, responseCapacity);
      }
      if (req.subCommand == kClientPinChangePin && (!pinSet_ || !req.pinHashEnc)) {
        return writeStatus(pinSet_ ? Ctap2Status::kMissingParameter : Ctap2Status::kPinNotSet, response,
                           responseCapacity);
      }

      uint8_t sharedSecret[64];
      if (!derivePinSharedSecret(req, sharedSecret)) {
        return writeStatus(Ctap2Status::kPinAuthInvalid, response, responseCapacity);
      }

      uint8_t authMessage[144];
      size_t authMessageLen = 0;
      if (req.newPinEncLen > sizeof(authMessage)) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        return writeStatus(Ctap2Status::kInvalidLength, response, responseCapacity);
      }
      memcpy(authMessage, req.newPinEnc, req.newPinEncLen);
      authMessageLen = req.newPinEncLen;
      if (req.subCommand == kClientPinChangePin) {
        if (authMessageLen + req.pinHashEncLen > sizeof(authMessage)) {
          memset(sharedSecret, 0, sizeof(sharedSecret));
          return writeStatus(Ctap2Status::kInvalidLength, response, responseCapacity);
        }
        memcpy(authMessage + authMessageLen, req.pinHashEnc, req.pinHashEncLen);
        authMessageLen += req.pinHashEncLen;
      }
      if (!clientPinVerify(sharedSecret, 32, authMessage, authMessageLen, req.pinUvAuthParam, req.pinUvAuthParamLen)) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        return writeStatus(Ctap2Status::kPinAuthInvalid, response, responseCapacity);
      }

      if (req.subCommand == kClientPinChangePin) {
        uint8_t pinHashPlain[32];
        size_t pinHashPlainLen = 0;
        if (!clientPinDecrypt(sharedSecret, req.pinHashEnc, req.pinHashEncLen, pinHashPlain, sizeof(pinHashPlain),
                              pinHashPlainLen) ||
            pinHashPlainLen < sizeof(storedPinHash_) ||
            memcmp(pinHashPlain, storedPinHash_, sizeof(storedPinHash_)) != 0) {
          memset(sharedSecret, 0, sizeof(sharedSecret));
          memset(pinHashPlain, 0, sizeof(pinHashPlain));
          return writeStatus(Ctap2Status::kPinInvalid, response, responseCapacity);
        }
        memset(pinHashPlain, 0, sizeof(pinHashPlain));
      }

      uint8_t newPinPlain[80];
      size_t newPinPlainLen = 0;
      if (!clientPinDecrypt(sharedSecret, req.newPinEnc, req.newPinEncLen, newPinPlain, sizeof(newPinPlain),
                            newPinPlainLen)) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        return writeStatus(Ctap2Status::kInvalidParameter, response, responseCapacity);
      }
      size_t pinLen = newPinPlainLen;
      while (pinLen > 0 && newPinPlain[pinLen - 1] == 0) pinLen--;
      if (pinLen < 4 || pinLen > 63) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        memset(newPinPlain, 0, sizeof(newPinPlain));
        return writeStatus(Ctap2Status::kPinPolicyViolation, response, responseCapacity);
      }
      uint8_t hash[32];
      if (!crypto_.sha256(newPinPlain, pinLen, hash)) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        memset(newPinPlain, 0, sizeof(newPinPlain));
        return writeStatus(Ctap2Status::kOther, response, responseCapacity);
      }
      memcpy(storedPinHash_, hash, sizeof(storedPinHash_));
      pinSet_ = true;
      pinRetries_ = kPinMaxRetries;
      pinMismatches_ = 0;
      savePinState();
      resetPinToken();
      memset(sharedSecret, 0, sizeof(sharedSecret));
      memset(newPinPlain, 0, sizeof(newPinPlain));
      memset(hash, 0, sizeof(hash));
      ux_.success(req.subCommand == kClientPinSetPin ? "PIN Set" : "PIN Changed");
      recordEvent("proof", "clientPin", "", "ok 0x00", false, false, true,
                  req.subCommand == kClientPinSetPin ? "PIN set" : "PIN changed", true);
      return writeStatus(Ctap2Status::kOk, response, responseCapacity);
    }

    case kClientPinGetPinToken:
    case kClientPinGetTokenWithPermissions: {
      if (!pinSet_) return writeStatus(Ctap2Status::kPinNotSet, response, responseCapacity);
      if (pinRetries_ == 0) return writeStatus(Ctap2Status::kPinBlocked, response, responseCapacity);
      if (!req.hasKeyAgreement || !req.pinHashEnc) {
        return writeStatus(Ctap2Status::kMissingParameter, response, responseCapacity);
      }

      uint8_t sharedSecret[64];
      uint8_t pinHashPlain[32];
      size_t pinHashPlainLen = 0;
      if (!derivePinSharedSecret(req, sharedSecret) ||
          !clientPinDecrypt(sharedSecret, req.pinHashEnc, req.pinHashEncLen, pinHashPlain, sizeof(pinHashPlain),
                            pinHashPlainLen) ||
          pinHashPlainLen < sizeof(storedPinHash_)) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        memset(pinHashPlain, 0, sizeof(pinHashPlain));
        return writeStatus(Ctap2Status::kPinAuthInvalid, response, responseCapacity);
      }
      if (memcmp(pinHashPlain, storedPinHash_, sizeof(storedPinHash_)) != 0) {
        if (pinRetries_ > 0) pinRetries_--;
        pinMismatches_++;
        savePinState();
        memset(sharedSecret, 0, sizeof(sharedSecret));
        memset(pinHashPlain, 0, sizeof(pinHashPlain));
        return writeStatus(pinRetries_ == 0 ? Ctap2Status::kPinBlocked : Ctap2Status::kPinInvalid, response,
                           responseCapacity);
      }

      pinRetries_ = kPinMaxRetries;
      pinMismatches_ = 0;
      pinTokenPermissions_ = req.hasPermissions ? req.permissions : 0xffffffffUL;
      strlcpy(pinTokenRpId_, req.rpId, sizeof(pinTokenRpId_));
      crypto_.randomBytes(pinUvAuthToken_, sizeof(pinUvAuthToken_));
      pinTokenInUse_ = true;
      savePinState();

      uint8_t tokenEnc[64];
      size_t tokenEncLen = 0;
      if (!clientPinEncrypt(sharedSecret, pinUvAuthToken_, sizeof(pinUvAuthToken_), tokenEnc, sizeof(tokenEnc),
                            tokenEncLen)) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        memset(pinHashPlain, 0, sizeof(pinHashPlain));
        return writeStatus(Ctap2Status::kOther, response, responseCapacity);
      }

      response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
      CborWriter writer(response + 1, responseCapacity - 1);
      writer.writeMap(1);
      writer.writeUInt(2);
      writer.writeBytes(tokenEnc, tokenEncLen);
      ux_.diagnostic("clientPin", "Token issued", req.rpId[0] ? req.rpId : "permissions");
      recordEvent("trace", "clientPin", req.rpId, "ok 0x00", false, false, true, "PIN/UV token issued");
      memset(sharedSecret, 0, sizeof(sharedSecret));
      memset(pinHashPlain, 0, sizeof(pinHashPlain));
      memset(tokenEnc, 0, sizeof(tokenEnc));
      return writer.ok() ? 1 + writer.size() : writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }

    default:
      ux_.diagnosticError("clientPin", "Unsupported cmd", "subcommand");
      return writeStatus(Ctap2Status::kInvalidParameter, response, responseCapacity);
  }
}

size_t Ctap2::handleMakeCredential(const uint8_t *payload, size_t len, uint8_t *response, size_t responseCapacity) {
  MakeCredentialRequest req{};
  if (!parseMakeCredential(payload, len, req)) {
    ux_.diagnosticError("makeCredential", "Invalid CBOR", "parse failed");
    recordEvent("error", "makeCredential", "", "invalid-cbor 0x12", false, false, false, "parse failed");
    return writeStatus(Ctap2Status::kInvalidCbor, response, responseCapacity);
  }
  if (isSyntheticRpId(req.rpId)) {
    // Chrome/macOS can issue makeCredential to the reserved ".dummy" RP as a
    // synthetic touch-collection step after a real ceremony. Collect BOOT, but
    // never create storage or assertion state for this reserved RP.
    const bool touched = waitForPresence("SYNTHETIC TOUCH", req.rpId);
    const char *status = touched ? "touch denied 0x27" : (canceled_ ? "canceled 0x27" : "timeout 0x27");
    ux_.trace("makeCredential", req.rpId, status, true);
    recordEvent("synthetic", "makeCredential", req.rpId, status, true, touched, false, "no credential created");
    return writeStatus(Ctap2Status::kOperationDenied, response, responseCapacity);
  }
  bool userVerified = false;
  if (req.requireUserVerification) {
    if (!req.hasPinUvAuthParam) {
      ux_.diagnosticError("makeCredential", "PIN required", "browser PIN");
      recordEvent("error", "makeCredential", req.rpId, pinSet_ ? "pin-required 0x36" : "pin-not-set 0x35",
                  false, false, false, "browser PIN required");
      return writeStatus(pinSet_ ? Ctap2Status::kPinRequired : Ctap2Status::kPinNotSet, response, responseCapacity);
    }
    if (!verifyPinUvAuthParam(req.pinUvAuthProtocol, req.clientDataHash, sizeof(req.clientDataHash),
                              req.pinUvAuthParam, req.pinUvAuthParamLen, kPinPermissionMakeCredential, req.rpId)) {
      ux_.diagnosticError("makeCredential", "PIN auth invalid", "browser PIN");
      recordEvent("error", "makeCredential", req.rpId, "pin-auth-invalid 0x33", false, false, false,
                  "browser PIN auth failed");
      return writeStatus(Ctap2Status::kPinAuthInvalid, response, responseCapacity);
    }
    userVerified = true;
  }
  CredentialRecord existing;
  if (req.excludeCredentialId &&
      ((req.excludeCredentialIdLen == 32 &&
        store_.findByCredentialId(req.excludeCredentialId, req.excludeCredentialIdLen, existing)) ||
       isStatelessCredentialId(req.excludeCredentialId, req.excludeCredentialIdLen, req.rpIdHash))) {
    ux_.diagnosticError("makeCredential", "Credential excluded", "already registered");
    recordEvent("error", "makeCredential", req.rpId, "credential-excluded 0x19", false, false, userVerified,
                "excludeList match");
    return writeStatus(Ctap2Status::kCredentialExcluded, response, responseCapacity);
  }
  ux_.diagnostic("makeCredential", "Waiting for BOOT", req.rpId);
  if (!waitForPresence("REGISTER", req.rpId)) {
    return writeStatus(canceled_ ? Ctap2Status::kKeepaliveCancel : Ctap2Status::kUserActionTimeout, response, responseCapacity);
  }

  const uint8_t mcFlags = userVerified ? 0x45 : 0x41;
  uint8_t authData[512];
  size_t authDataLen = 0;

  if (req.requireResidentKey) {
    // Resident/discoverable credential: stored in NVS, subject to the cap.
    P256KeyPair key;
    CredentialRecord record{};
    record.magic = kCredentialRecordMagic;
    record.version = kCredentialRecordVersion;
    record.flags = kCredentialFlagResident;
    if (!crypto_.generateP256(key) || !crypto_.randomBytes(record.credentialId, sizeof(record.credentialId))) {
      ux_.diagnosticError("makeCredential", "Crypto failed", "key or random");
      recordEvent("error", "makeCredential", req.rpId, "other 0x7f", false, true, userVerified, "crypto failed");
      return writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }
    memcpy(record.rpIdHash, req.rpIdHash, sizeof(record.rpIdHash));
    strlcpy(record.rpId, req.rpId, sizeof(record.rpId));
    strlcpy(record.rpName, req.rpName[0] ? req.rpName : req.rpId, sizeof(record.rpName));
    memcpy(record.userHandle, req.userHandle, req.userHandleLen);
    record.userHandleLen = req.userHandleLen;
    strlcpy(record.userName, req.userName[0] ? req.userName : "user", sizeof(record.userName));
    strlcpy(record.userDisplayName, req.userDisplayName[0] ? req.userDisplayName : record.userName,
            sizeof(record.userDisplayName));
    memcpy(record.privateKey, key.privateKey, 32);
    memcpy(record.publicX, key.publicX, 32);
    memcpy(record.publicY, key.publicY, 32);
    record.signCount = 1;
    if (!store_.add(record)) {
      ux_.diagnosticError("makeCredential", "Storage full", "delete or reset");
      recordEvent("error", "makeCredential", req.rpId, "keystore-full 0x28", false, true, userVerified,
                  "resident store full");
      return writeStatus(Ctap2Status::kKeyStoreFull, response, responseCapacity);
    }
    if (!buildAuthData(record.rpIdHash, mcFlags, record.signCount, record.credentialId, 32, record.publicX,
                       record.publicY, authData, sizeof(authData), authDataLen)) {
      ux_.diagnosticError("makeCredential", "AuthData failed", "encode failed");
      recordEvent("error", "makeCredential", req.rpId, "other 0x7f", false, true, userVerified,
                  "authData encode failed");
      return writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }
    ux_.trace("makeCredential", record.rpId, "registered 0x00", false);
  } else {
    // Non-resident credential: stateless key-wrapping. Nothing is stored; the
    // key is re-derived at assertion from the credential ID. No cap, no NVS write.
    uint8_t credId[kStatelessCredIdLen];
    P256KeyPair key;
    if (!buildStatelessCredentialId(req.rpIdHash, credId, key)) {
      ux_.diagnosticError("makeCredential", "Crypto failed", "wrap failed");
      recordEvent("error", "makeCredential", req.rpId, "other 0x7f", false, true, userVerified,
                  "stateless wrap failed");
      return writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }
    if (!buildAuthData(req.rpIdHash, mcFlags, masterSecret_.currentSignCount(), credId, kStatelessCredIdLen,
                       key.publicX, key.publicY, authData, sizeof(authData), authDataLen)) {
      ux_.diagnosticError("makeCredential", "AuthData failed", "encode failed");
      recordEvent("error", "makeCredential", req.rpId, "other 0x7f", false, true, userVerified,
                  "authData encode failed");
      return writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }
    memset(key.privateKey, 0, sizeof(key.privateKey));
    ux_.trace("makeCredential", req.rpId, "registered (stateless) 0x00", false);
  }

  response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
  CborWriter writer(response + 1, responseCapacity - 1);
  writer.writeMap(3);
  writer.writeUInt(1);
  writer.writeText("none");
  writer.writeUInt(2);
  writer.writeBytes(authData, authDataLen);
  writer.writeUInt(3);
  writer.writeMap(0);
  if (!writer.ok()) {
    ux_.diagnosticError("makeCredential", "Response failed", "CBOR encode");
    recordEvent("error", "makeCredential", req.rpId, "other 0x7f", false, true, userVerified,
                "response encode failed");
    return writeStatus(Ctap2Status::kOther, response, responseCapacity);
  }
  recordEvent("proof", "makeCredential", req.rpId, "registered 0x00", false, true, userVerified,
              req.requireResidentKey ? "discoverable credential" : "non-discoverable stateless credential", true);
  ux_.success("Registered");
  return 1 + writer.size();
}

size_t Ctap2::handleGetAssertion(const uint8_t *payload, size_t len, uint8_t *response, size_t responseCapacity) {
  GetAssertionRequest req{};
  if (!parseGetAssertion(payload, len, req)) {
    ux_.diagnosticError("getAssertion", "Invalid CBOR", "parse failed");
    recordEvent("error", "getAssertion", "", "invalid-cbor 0x12", false, false, false, "parse failed");
    return writeStatus(Ctap2Status::kInvalidCbor, response, responseCapacity);
  }
  if (isSyntheticRpId(req.rpId)) {
    // ".dummy" is Chrome's reserved synthetic/fallback RP. Reject silently with
    // no-credentials: no BOOT, no screen repaint, and crucially do NOT touch the
    // cached assertion chain so an in-flight real-RP login / getNextAssertion is
    // left undisturbed.
    ux_.trace("getAssertion", req.rpId, "no-credentials 0x2e", true);
    recordEvent("synthetic", "getAssertion", req.rpId, "no-credentials 0x2e", true, false, false,
                "reserved RP");
    return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
  }
  bool userVerified = false;
  if (req.requireUserVerification) {
    if (!req.hasPinUvAuthParam) {
      ux_.diagnosticError("getAssertion", "PIN required", "browser PIN");
      recordEvent("error", "getAssertion", req.rpId, pinSet_ ? "pin-required 0x36" : "pin-not-set 0x35",
                  false, false, false, "browser PIN required");
      return writeStatus(pinSet_ ? Ctap2Status::kPinRequired : Ctap2Status::kPinNotSet, response, responseCapacity);
    }
    if (!verifyPinUvAuthParam(req.pinUvAuthProtocol, req.clientDataHash, sizeof(req.clientDataHash),
                              req.pinUvAuthParam, req.pinUvAuthParamLen, kPinPermissionGetAssertion, req.rpId)) {
      ux_.diagnosticError("getAssertion", "PIN auth invalid", "browser PIN");
      recordEvent("error", "getAssertion", req.rpId, "pin-auth-invalid 0x33", false, false, false,
                  "browser PIN auth failed");
      return writeStatus(Ctap2Status::kPinAuthInvalid, response, responseCapacity);
    }
    userVerified = true;
  }
  CredentialRecord record;
  size_t recordIndex = 0;
  assertionCount_ = 0;
  assertionNext_ = 0;

  // Stateless-first: scan the allowList for a credential ID this device minted
  // (its MAC verifies under rpIdHash) and re-derive its key without touching NVS.
  P256KeyPair statelessKey;
  const uint8_t *statelessCredId = nullptr;
  size_t statelessCredIdLen = 0;
  bool statelessHit = false;
  if (req.hasAllowList) {
    for (size_t i = 0; i < req.allowListCount && !statelessHit; ++i) {
      if (isStatelessCredentialId(req.allowList[i].id, req.allowList[i].idLen, req.rpIdHash) &&
          deriveStatelessKey(req.allowList[i].id, req.rpIdHash, statelessKey)) {
        statelessCredId = req.allowList[i].id;
        statelessCredIdLen = req.allowList[i].idLen;
        statelessHit = true;
      }
    }
    if (!statelessHit) {
      // Resident / legacy stored credential: try each allowList entry in turn.
      for (size_t i = 0; i < req.allowListCount; ++i) {
        if (store_.findByRpIdHashAndAllowList(req.rpIdHash, req.allowList[i].id, req.allowList[i].idLen, record,
                                              &recordIndex)) {
          assertionIndexes_[assertionCount_++] = recordIndex;
          break;
        }
      }
    }
  } else {
    // Empty allowList: discoverable (resident) credentials only. Stateless creds
    // are non-discoverable by design and correctly never appear here.
    assertionCount_ = store_.collectByRpIdHash(req.rpIdHash, true, assertionIndexes_, BuildConfig::kMaxCredentials);
    if (assertionCount_ > 0) {
      recordIndex = assertionIndexes_[0];
      store_.load(recordIndex, record);
    }
  }

  const bool requireUp = req.userPresenceRequested;
  if (!statelessHit && assertionCount_ == 0) {
    if (requireUp) {
      ux_.diagnosticError("getAssertion", "No credential", req.rpId);
      recordEvent("error", "getAssertion", req.rpId, "no-credentials 0x2e", false, false, userVerified,
                  "no matching credential");
    } else {
      ux_.trace("getAssertion", req.rpId, "preflight no-cred 0x2e", false);
      recordEvent("trace", "getAssertion", req.rpId, "preflight no-cred 0x2e", false, false, userVerified,
                  "silent up=false preflight");
    }
    return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
  }
  // up=false is Chrome's silent pre-flight to discover which authenticator holds
  // the credential. Honor it: no presence wait and no screen change; the response
  // carries a cleared UP flag so the browser still issues the real up=true ceremony.
  if (requireUp) {
    ux_.diagnostic("getAssertion", "Waiting for BOOT", req.rpId);
    if (!waitForPresence("LOGIN", req.rpId)) {
      return writeStatus(canceled_ ? Ctap2Status::kKeepaliveCancel : Ctap2Status::kUserActionTimeout, response,
                         responseCapacity);
    }
  }

  if (statelessHit) {
    AssertionIdentity identity{};
    memcpy(identity.rpIdHash, req.rpIdHash, sizeof(identity.rpIdHash));
    memcpy(identity.privateKey, statelessKey.privateKey, sizeof(identity.privateKey));
    identity.credentialId = statelessCredId;
    identity.credentialIdLen = statelessCredIdLen;
    identity.rpId = req.rpId;
    identity.hasUser = false;  // non-resident creds carry no stored user entity
    const uint32_t sc = requireUp ? masterSecret_.nextSignCount() : masterSecret_.currentSignCount();
    const size_t n = writeAssertionFromIdentity(identity, req.clientDataHash, response, responseCapacity, false, 1,
                                                userVerified, requireUp, sc);
    memset(statelessKey.privateKey, 0, sizeof(statelessKey.privateKey));
    memset(identity.privateKey, 0, sizeof(identity.privateKey));
    return n;
  }

  memcpy(assertionClientDataHash_, req.clientDataHash, sizeof(assertionClientDataHash_));
  assertionUserVerified_ = userVerified;
  assertionNext_ = 1;
  return writeAssertionResponse(recordIndex, req.clientDataHash, response, responseCapacity, assertionCount_ > 1,
                                assertionCount_, userVerified, requireUp);
}

size_t Ctap2::handleGetNextAssertion(uint8_t *response, size_t responseCapacity) {
  if (assertionNext_ >= assertionCount_) {
    ux_.diagnosticError("getNextAssertion", "No cached assertion", "start login first");
    return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
  }
  const size_t recordIndex = assertionIndexes_[assertionNext_++];
  return writeAssertionResponse(recordIndex, assertionClientDataHash_, response, responseCapacity, false, assertionCount_,
                                assertionUserVerified_, true);
}

size_t Ctap2::writeAssertionResponse(size_t recordIndex, const uint8_t clientDataHash[32], uint8_t *response,
                                     size_t responseCapacity, bool includeCredentialCount, size_t credentialCount,
                                     bool userVerified, bool userPresent) {
  CredentialRecord record;
  if (!store_.load(recordIndex, record)) {
    ux_.diagnosticError("getAssertion", "No credential", "cached record missing");
    return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
  }
  // Only a real, user-present assertion advances and persists the per-credential
  // counter; a silent up=false pre-flight signs with the current value.
  const uint32_t signCount = record.signCount + (userPresent ? 1 : 0);

  AssertionIdentity identity{};
  memcpy(identity.rpIdHash, record.rpIdHash, sizeof(identity.rpIdHash));
  memcpy(identity.privateKey, record.privateKey, sizeof(identity.privateKey));
  identity.credentialId = record.credentialId;
  identity.credentialIdLen = 32;
  identity.rpId = record.rpId;
  identity.hasUser = true;
  identity.userHandle = record.userHandle;
  identity.userHandleLen = record.userHandleLen;
  identity.userName = record.userName;
  identity.userDisplayName = record.userDisplayName;

  const size_t n = writeAssertionFromIdentity(identity, clientDataHash, response, responseCapacity,
                                              includeCredentialCount, credentialCount, userVerified, userPresent,
                                              signCount);
  if (userPresent && n > 1) store_.updateCounter(recordIndex, signCount);
  memset(identity.privateKey, 0, sizeof(identity.privateKey));
  return n;
}

size_t Ctap2::writeAssertionFromIdentity(const AssertionIdentity &identity, const uint8_t clientDataHash[32],
                                         uint8_t *response, size_t responseCapacity, bool includeCredentialCount,
                                         size_t credentialCount, bool userVerified, bool userPresent,
                                         uint32_t signCount) {
  const uint8_t flags = static_cast<uint8_t>((userPresent ? 0x01 : 0x00) | (userVerified ? 0x04 : 0x00));
  uint8_t authData[64];
  size_t authDataLen = 0;
  if (!buildAuthData(identity.rpIdHash, flags, signCount, nullptr, 0, nullptr, nullptr, authData, sizeof(authData),
                     authDataLen)) {
    ux_.diagnosticError("getAssertion", "AuthData failed", "encode failed");
    recordEvent("error", "getAssertion", identity.rpId ? identity.rpId : "", "other 0x7f", false, userPresent,
                userVerified, "authData encode failed");
    return writeStatus(Ctap2Status::kOther, response, responseCapacity);
  }

  uint8_t signedBytes[96];
  memcpy(signedBytes, authData, authDataLen);
  memcpy(signedBytes + authDataLen, clientDataHash, 32);
  uint8_t signatureHash[32];
  uint8_t signature[96];
  size_t signatureLen = 0;
  if (!crypto_.sha256(signedBytes, authDataLen + 32, signatureHash) ||
      !crypto_.signP256Der(identity.privateKey, signatureHash, signature, sizeof(signature), signatureLen)) {
    ux_.diagnosticError("getAssertion", "Crypto failed", "sign failed");
    recordEvent("error", "getAssertion", identity.rpId ? identity.rpId : "", "other 0x7f", false, userPresent,
                userVerified, "signature failed");
    return writeStatus(Ctap2Status::kOther, response, responseCapacity);
  }

  size_t mapCount = 3;  // credential, authData, signature
  if (identity.hasUser) mapCount++;
  if (includeCredentialCount) mapCount++;

  response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
  CborWriter writer(response + 1, responseCapacity - 1);
  writer.writeMap(mapCount);
  writer.writeUInt(1);
  writer.writeMap(2);
  // CTAP2 canonical CBOR: map keys sorted shortest-first, then bytewise. "id"
  // (2 bytes) must precede "type" (4 bytes) or Chrome's strict response parser
  // rejects the assertion and the WebAuthn touch dialog hangs open.
  writer.writeText("id");
  writer.writeBytes(identity.credentialId, identity.credentialIdLen);
  writer.writeText("type");
  writer.writeText("public-key");
  writer.writeUInt(2);
  writer.writeBytes(authData, authDataLen);
  writer.writeUInt(3);
  writer.writeBytes(signature, signatureLen);
  if (identity.hasUser) {
    const bool includeIdentifyingUserInfo = userVerified;
    const bool hasName = includeIdentifyingUserInfo && identity.userName && identity.userName[0];
    const bool hasDisplay = includeIdentifyingUserInfo && identity.userDisplayName && identity.userDisplayName[0];
    writer.writeUInt(4);
    writer.writeMap(1 + (hasName ? 1 : 0) + (hasDisplay ? 1 : 0));
    writer.writeText("id");
    writer.writeBytes(identity.userHandle, identity.userHandleLen);
    if (hasName) {
      writer.writeText("name");
      writer.writeText(identity.userName);
    }
    if (hasDisplay) {
      writer.writeText("displayName");
      writer.writeText(identity.userDisplayName);
    }
  }
  if (includeCredentialCount) {
    writer.writeUInt(5);
    writer.writeUInt(credentialCount);
  }
  const char *traceRp = identity.rpId ? identity.rpId : "";
  if (!writer.ok()) {
    ux_.diagnosticError("getAssertion", "Response failed", "CBOR encode");
    recordEvent("error", "getAssertion", traceRp, "other 0x7f", false, userPresent, userVerified,
                "response encode failed");
    return writeStatus(Ctap2Status::kOther, response, responseCapacity);
  }
  if (userPresent) {
    ux_.trace("getAssertion", traceRp, "signed 0x00", false);
    recordEvent("proof", "getAssertion", traceRp, "signed 0x00", false, true, userVerified,
                identity.hasUser ? "discoverable credential" : "non-discoverable credential", true);
    ux_.success("Signed");
  } else {
    // Silent pre-flight succeeded (UP flag cleared); leave the screen alone.
    ux_.trace("getAssertion", traceRp, "preflight up=0 0x00", false);
    recordEvent("trace", "getAssertion", traceRp, "preflight up=0 0x00", false, false, userVerified,
                "silent up=false preflight");
  }
  return 1 + writer.size();
}

void Ctap2::writeRpEntity(CborWriter &writer, const CredentialRecord &record) {
  writer.writeMap(2);
  writer.writeText("id");
  writer.writeText(record.rpId);
  writer.writeText("name");
  writer.writeText(record.rpName[0] ? record.rpName : record.rpId);
}

void Ctap2::writeUserEntity(CborWriter &writer, const CredentialRecord &record) {
  writer.writeMap(record.userDisplayName[0] ? 3 : 2);
  writer.writeText("id");
  writer.writeBytes(record.userHandle, record.userHandleLen);
  writer.writeText("name");
  writer.writeText(record.userName);
  if (record.userDisplayName[0]) {
    writer.writeText("displayName");
    writer.writeText(record.userDisplayName);
  }
}

void Ctap2::writeCredentialDescriptor(CborWriter &writer, const CredentialRecord &record) {
  writer.writeMap(2);
  // Canonical CBOR: "id" (shorter key) before "type" (see writeAssertionFromIdentity).
  writer.writeText("id");
  writer.writeBytes(record.credentialId, 32);
  writer.writeText("type");
  writer.writeText("public-key");
}

size_t Ctap2::writeCredentialManagementRp(size_t recordIndex, uint8_t *response, size_t responseCapacity,
                                          bool includeTotal) {
  CredentialRecord record;
  if (!store_.load(recordIndex, record)) {
    return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
  }
  response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
  CborWriter writer(response + 1, responseCapacity - 1);
  writer.writeMap(includeTotal ? 3 : 2);
  writer.writeUInt(3);
  writeRpEntity(writer, record);
  writer.writeUInt(4);
  writer.writeBytes(record.rpIdHash, 32);
  if (includeTotal) {
    writer.writeUInt(5);
    writer.writeUInt(cmRpCount_);
  }
  return writer.ok() ? 1 + writer.size() : writeStatus(Ctap2Status::kOther, response, responseCapacity);
}

size_t Ctap2::writeCredentialManagementCredential(size_t recordIndex, uint8_t *response,
                                                  size_t responseCapacity, bool includeTotal) {
  CredentialRecord record;
  if (!store_.load(recordIndex, record)) {
    return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
  }
  response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
  CborWriter writer(response + 1, responseCapacity - 1);
  writer.writeMap(includeTotal ? 4 : 3);
  writer.writeUInt(6);
  writeUserEntity(writer, record);
  writer.writeUInt(7);
  writeCredentialDescriptor(writer, record);
  writer.writeUInt(8);
  writeCoseKey(writer, record.publicX, record.publicY);
  if (includeTotal) {
    writer.writeUInt(9);
    writer.writeUInt(cmCredentialCount_);
  }
  return writer.ok() ? 1 + writer.size() : writeStatus(Ctap2Status::kOther, response, responseCapacity);
}

size_t Ctap2::handleCredentialManagement(const uint8_t *payload, size_t len, uint8_t *response,
                                         size_t responseCapacity) {
  CredentialManagementRequest req{};
  if (!parseCredentialManagement(payload, len, req)) {
    ux_.diagnosticError("credMgmt", "Invalid CBOR", "parse failed");
    recordEvent("error", "credMgmt", "", "invalid-cbor 0x12", false, false, false, "parse failed");
    return writeStatus(Ctap2Status::kInvalidCbor, response, responseCapacity);
  }

  switch (req.subCommand) {
    case kCredMgmtGetCredsMetadata: {
      response[0] = static_cast<uint8_t>(Ctap2Status::kOk);
      CborWriter writer(response + 1, responseCapacity - 1);
      writer.writeMap(2);
      writer.writeUInt(1);
      writer.writeUInt(store_.residentCount());
      writer.writeUInt(2);
      writer.writeUInt(store_.remainingSlots());
      ux_.diagnostic("credMgmt", "Metadata", "resident count");
      recordEvent("trace", "credMgmt", "", "ok 0x00", false, false, false, "metadata");
      return writer.ok() ? 1 + writer.size() : writeStatus(Ctap2Status::kOther, response, responseCapacity);
    }

    case kCredMgmtEnumerateRpsBegin: {
      cmRpCount_ = 0;
      cmRpNext_ = 0;
      for (size_t i = 0; i < store_.count() && cmRpCount_ < BuildConfig::kMaxCredentials; ++i) {
        CredentialRecord record;
        if (!store_.load(i, record) || !(record.flags & kCredentialFlagResident)) continue;
        bool seen = false;
        for (size_t n = 0; n < cmRpCount_; ++n) {
          CredentialRecord existing;
          if (store_.load(cmRpIndexes_[n], existing) && memcmp(existing.rpIdHash, record.rpIdHash, 32) == 0) {
            seen = true;
            break;
          }
        }
        if (!seen) cmRpIndexes_[cmRpCount_++] = i;
      }
      if (cmRpCount_ == 0) {
        ux_.diagnosticError("credMgmt", "No resident RPs", "nothing to list");
        recordEvent("error", "credMgmt", "", "no-credentials 0x2e", false, false, false, "no resident RPs");
        return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
      }
      ux_.diagnostic("credMgmt", "Enumerate RPs", "resident creds");
      recordEvent("trace", "credMgmt", "", "ok 0x00", false, false, false, "enumerate RPs");
      cmRpNext_ = 1;
      return writeCredentialManagementRp(cmRpIndexes_[0], response, responseCapacity, true);
    }

    case kCredMgmtEnumerateRpsGetNextRp:
      if (cmRpNext_ >= cmRpCount_) {
        return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
      }
      return writeCredentialManagementRp(cmRpIndexes_[cmRpNext_++], response, responseCapacity, false);

    case kCredMgmtEnumerateCredentialsBegin:
      if (!req.hasRpIdHash) {
        return writeStatus(Ctap2Status::kMissingParameter, response, responseCapacity);
      }
      cmCredentialCount_ = store_.collectByRpIdHash(req.rpIdHash, true, cmCredentialIndexes_, BuildConfig::kMaxCredentials);
      cmCredentialNext_ = 0;
      if (cmCredentialCount_ == 0) {
        ux_.diagnosticError("credMgmt", "No credentials", "for RP");
        recordEvent("error", "credMgmt", "", "no-credentials 0x2e", false, false, false, "no resident credentials");
        return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
      }
      ux_.diagnostic("credMgmt", "Enumerate creds", "resident RP");
      recordEvent("trace", "credMgmt", "", "ok 0x00", false, false, false, "enumerate credentials");
      cmCredentialNext_ = 1;
      return writeCredentialManagementCredential(cmCredentialIndexes_[0], response, responseCapacity, true);

    case kCredMgmtEnumerateCredentialsGetNextCredential:
      if (cmCredentialNext_ >= cmCredentialCount_) {
        return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
      }
      return writeCredentialManagementCredential(cmCredentialIndexes_[cmCredentialNext_++], response, responseCapacity, false);

    case kCredMgmtDeleteCredential:
      if (!req.hasCredentialId) {
        return writeStatus(Ctap2Status::kMissingParameter, response, responseCapacity);
      }
      ux_.diagnostic("credMgmt", "Delete credential", "Waiting for BOOT");
      if (!waitForPresence("DELETE", "credential")) {
        return writeStatus(canceled_ ? Ctap2Status::kKeepaliveCancel : Ctap2Status::kUserActionTimeout, response, responseCapacity);
      }
      if (!store_.removeByCredentialId(req.credentialId, req.credentialIdLen)) {
        return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
      }
      ux_.success("Credential Deleted");
      recordEvent("proof", "credMgmt", "", "ok 0x00", false, true, false, "credential deleted", true);
      return writeStatus(Ctap2Status::kOk, response, responseCapacity);

    case kCredMgmtUpdateUserInformation: {
      if (!req.hasCredentialId || !req.hasUser) {
        return writeStatus(Ctap2Status::kMissingParameter, response, responseCapacity);
      }
      CredentialRecord record;
      size_t index = 0;
      if (!store_.findByCredentialId(req.credentialId, req.credentialIdLen, record, &index)) {
        return writeStatus(Ctap2Status::kNoCredentials, response, responseCapacity);
      }
      ux_.diagnostic("credMgmt", "Update user", "Waiting for BOOT");
      if (!waitForPresence("UPDATE", record.rpId)) {
        return writeStatus(canceled_ ? Ctap2Status::kKeepaliveCancel : Ctap2Status::kUserActionTimeout, response, responseCapacity);
      }
      memcpy(record.userHandle, req.userHandle, req.userHandleLen);
      record.userHandleLen = req.userHandleLen;
      strlcpy(record.userName, req.userName[0] ? req.userName : record.userName, sizeof(record.userName));
      strlcpy(record.userDisplayName, req.userDisplayName[0] ? req.userDisplayName : record.userName,
              sizeof(record.userDisplayName));
      if (!store_.update(index, record)) {
        return writeStatus(Ctap2Status::kOther, response, responseCapacity);
      }
      ux_.success("User Updated");
      recordEvent("proof", "credMgmt", record.rpId, "ok 0x00", false, true, false, "user info updated", true);
      return writeStatus(Ctap2Status::kOk, response, responseCapacity);
    }

    default:
      ux_.diagnosticError("credMgmt", "Unsupported cmd", "subcommand");
      recordEvent("error", "credMgmt", "", "invalid-parameter 0x02", false, false, false, "unsupported subcommand");
      return writeStatus(Ctap2Status::kInvalidParameter, response, responseCapacity);
  }
}

size_t Ctap2::handleReset(uint8_t *response, size_t responseCapacity) {
  ux_.waitingForPresence("RESET", "hold BOOT");
  if (!presence_.waitForResetHold(BuildConfig::kResetHoldMs, BuildConfig::kUserPresenceTimeoutMs)) {
    ux_.diagnosticError("RESET", "Timeout", "hold BOOT 5s");
    recordEvent("timeout", "reset", "", "timeout 0x2f", false, false, false, "reset hold not detected");
    return writeStatus(Ctap2Status::kUserActionTimeout, response, responseCapacity);
  }
  wipeLabState();
  recordEvent("proof", "reset", "", "ok 0x00", false, true, false, "host CTAP reset wiped lab state", true);
  ux_.success("Wiped");
  return writeStatus(Ctap2Status::kOk, response, responseCapacity);
}
