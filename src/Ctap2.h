#pragma once

#include <Arduino.h>
#include <Preferences.h>

#include "AmoledUx.h"
#include "CborCodec.h"
#include "CredentialStore.h"
#include "CryptoProvider.h"
#include "LabRecorder.h"
#include "MasterSecret.h"
#include "UserPresence.h"

enum class Ctap2Status : uint8_t {
  kOk = 0x00,
  kInvalidCommand = 0x01,
  kInvalidParameter = 0x02,
  kInvalidLength = 0x03,
  kInvalidCbor = 0x12,
  kMissingParameter = 0x14,
  kCredentialExcluded = 0x19,
  kOperationDenied = 0x27,
  kKeyStoreFull = 0x28,
  kUnsupportedOption = 0x2b,
  kKeepaliveCancel = 0x2d,
  kNoCredentials = 0x2e,
  kUserActionTimeout = 0x2f,
  kPinInvalid = 0x31,
  kPinBlocked = 0x32,
  kPinAuthInvalid = 0x33,
  kPinAuthBlocked = 0x34,
  kPinNotSet = 0x35,
  kPinRequired = 0x36,
  kPinPolicyViolation = 0x37,
  kOther = 0x7f,
};

class Ctap2 {
 public:
  using KeepaliveCallback = void (*)(void *ctx, uint8_t status);

  Ctap2(CryptoProvider &crypto, CredentialStore &store, UserPresence &presence, AmoledUx &ux,
        LabRecorder &recorder);

  void begin();
  void setKeepaliveCallback(KeepaliveCallback callback, void *ctx);
  size_t handle(const uint8_t *request, size_t requestLen, uint8_t *response, size_t responseCapacity);
  size_t handleCtap1(const uint8_t *request, size_t requestLen, uint8_t *response, size_t responseCapacity);
  void wipeLabState();
  void cancel();
  bool isPinSet() const { return pinSet_; }

 private:
  // Stateless (key-wrapped) non-resident credential ID: [version:1][nonce:16][MAC:16].
  // The private key is derived from (master secret, nonce, rpIdHash), never stored;
  // the MAC binds rpIdHash so an ID cannot be replayed against another RP.
  static constexpr uint8_t kStatelessCredIdVersion = 0x01;
  static constexpr size_t kStatelessNonceLen = 16;
  static constexpr size_t kStatelessMacLen = 16;
  static constexpr size_t kStatelessCredIdLen = 1 + kStatelessNonceLen + kStatelessMacLen;  // 33
  static constexpr size_t kMaxAllowListEntries = 16;

  struct CredentialDescriptorView {
    const uint8_t *id = nullptr;
    size_t idLen = 0;
  };

  // Signing identity for an assertion, decoupled from the credential store so a
  // resident record and a re-derived stateless key share one code path.
  struct AssertionIdentity {
    uint8_t rpIdHash[32] = {};
    uint8_t privateKey[32] = {};
    const uint8_t *credentialId = nullptr;
    size_t credentialIdLen = 0;
    const char *rpId = nullptr;  // for the on-device trace line
    bool hasUser = false;        // resident creds carry a user entity; stateless omit it
    const uint8_t *userHandle = nullptr;
    size_t userHandleLen = 0;
    const char *userName = nullptr;
    const char *userDisplayName = nullptr;
  };

  struct MakeCredentialRequest {
    uint8_t clientDataHash[32];
    char rpId[64];
    uint8_t rpIdHash[32];
    char rpName[48];
    uint8_t userHandle[64];
    size_t userHandleLen = 0;
    char userName[48];
    char userDisplayName[48];
    bool hasClientDataHash = false;
    bool hasRpId = false;
    bool hasUser = false;
    bool supportsEs256 = false;
    bool requireResidentKey = false;
    bool requireUserVerification = false;
    const uint8_t *pinUvAuthParam = nullptr;
    size_t pinUvAuthParamLen = 0;
    uint8_t pinUvAuthProtocol = 0;
    bool hasPinUvAuthParam = false;
    const uint8_t *excludeCredentialId = nullptr;
    size_t excludeCredentialIdLen = 0;
  };

  struct GetAssertionRequest {
    char rpId[64];
    uint8_t rpIdHash[32];
    uint8_t clientDataHash[32];
    CredentialDescriptorView allowList[kMaxAllowListEntries];
    size_t allowListCount = 0;
    bool hasRpId = false;
    bool hasClientDataHash = false;
    bool hasAllowList = false;
    bool requireUserVerification = false;
    // CTAP2 "up" option. Defaults to true; Chrome sets it false for the silent
    // pre-flight that discovers which authenticator holds a credential. A false
    // value must skip user presence and clear the UP authData flag.
    bool userPresenceRequested = true;
    const uint8_t *pinUvAuthParam = nullptr;
    size_t pinUvAuthParamLen = 0;
    uint8_t pinUvAuthProtocol = 0;
    bool hasPinUvAuthParam = false;
  };

  struct U2fApdu {
    uint8_t cla = 0;
    uint8_t ins = 0;
    uint8_t p1 = 0;
    uint8_t p2 = 0;
    const uint8_t *data = nullptr;
    size_t dataLen = 0;
  };

  struct CredentialManagementRequest {
    uint8_t subCommand = 0;
    uint8_t rpIdHash[32];
    bool hasRpIdHash = false;
    const uint8_t *credentialId = nullptr;
    size_t credentialIdLen = 0;
    bool hasCredentialId = false;
    uint8_t userHandle[64];
    size_t userHandleLen = 0;
    char userName[48];
    char userDisplayName[48];
    bool hasUser = false;
  };

  struct ClientPinRequest {
    uint8_t pinUvAuthProtocol = 0;
    uint8_t subCommand = 0;
    uint8_t peerX[32] = {};
    uint8_t peerY[32] = {};
    bool hasKeyAgreement = false;
    const uint8_t *pinUvAuthParam = nullptr;
    size_t pinUvAuthParamLen = 0;
    const uint8_t *newPinEnc = nullptr;
    size_t newPinEncLen = 0;
    const uint8_t *pinHashEnc = nullptr;
    size_t pinHashEncLen = 0;
    uint32_t permissions = 0;
    bool hasPermissions = false;
    char rpId[64] = {};
  };

  size_t writeStatus(Ctap2Status status, uint8_t *response, size_t responseCapacity);
  size_t handleGetInfo(uint8_t *response, size_t responseCapacity);
  size_t handleMakeCredential(const uint8_t *payload, size_t len, uint8_t *response, size_t responseCapacity);
  size_t handleGetAssertion(const uint8_t *payload, size_t len, uint8_t *response, size_t responseCapacity);
  size_t handleClientPin(const uint8_t *payload, size_t len, uint8_t *response, size_t responseCapacity);
  size_t handleGetNextAssertion(uint8_t *response, size_t responseCapacity);
  size_t handleCredentialManagement(const uint8_t *payload, size_t len, uint8_t *response, size_t responseCapacity);
  size_t handleReset(uint8_t *response, size_t responseCapacity);
  size_t handleU2fVersion(uint8_t *response, size_t responseCapacity);
  size_t handleU2fRegister(const U2fApdu &apdu, uint8_t *response, size_t responseCapacity);
  size_t handleU2fAuthenticate(const U2fApdu &apdu, uint8_t *response, size_t responseCapacity);

  bool parseMakeCredential(const uint8_t *payload, size_t len, MakeCredentialRequest &out);
  bool parseGetAssertion(const uint8_t *payload, size_t len, GetAssertionRequest &out);
  bool parseClientPin(const uint8_t *payload, size_t len, ClientPinRequest &out);
  bool parseCoseP256(CborReader &reader, uint8_t x[32], uint8_t y[32]);
  bool parseCredentialManagement(const uint8_t *payload, size_t len, CredentialManagementRequest &out);
  bool parseCredentialManagementParams(CborReader &reader, CredentialManagementRequest &out);
  bool parseCredentialManagementUser(CborReader &reader, CredentialManagementRequest &out);
  bool parseU2fApdu(const uint8_t *request, size_t requestLen, U2fApdu &out);
  size_t writeU2fStatus(uint16_t status, uint8_t *response, size_t responseCapacity);
  bool parseRpMap(CborReader &reader, MakeCredentialRequest &out);
  bool parseUserMap(CborReader &reader, MakeCredentialRequest &out);
  bool parsePubKeyCredParams(CborReader &reader, MakeCredentialRequest &out);
  bool parseOptions(CborReader &reader, bool &rk, bool &uv, bool *up = nullptr);
  bool parseCredentialDescriptor(CborReader &reader, const uint8_t *&id, size_t &idLen);
  bool waitForPresence(const char *action, const char *rpId, bool sendKeepalive = true);
  bool writeCoseKey(CborWriter &writer, const uint8_t x[32], const uint8_t y[32]);
  bool writeKeyAgreement(CborWriter &writer);
  bool derivePinSharedSecret(const ClientPinRequest &req, uint8_t sharedSecret[64]);
  bool clientPinDecrypt(const uint8_t sharedSecret[64], const uint8_t *cipher, size_t cipherLen, uint8_t *plain,
                        size_t plainCapacity, size_t &plainLen);
  bool clientPinEncrypt(const uint8_t sharedSecret[64], const uint8_t *plain, size_t plainLen, uint8_t *cipher,
                        size_t cipherCapacity, size_t &cipherLen);
  bool clientPinVerify(const uint8_t *key, size_t keyLen, const uint8_t *message, size_t messageLen,
                       const uint8_t *signature, size_t signatureLen);
  bool verifyPinUvAuthParam(uint8_t protocol, const uint8_t *message, size_t messageLen, const uint8_t *signature,
                            size_t signatureLen, uint8_t permission, const char *rpId);
  void resetPinToken();
  void loadPinState();
  void savePinState();
  void clearPinState();
  bool buildAuthData(const uint8_t rpIdHash[32], uint8_t flags, uint32_t signCount, const uint8_t *attestedCredId,
                     size_t attestedCredIdLen, const uint8_t *attestedPubX, const uint8_t *attestedPubY, uint8_t *out,
                     size_t outCapacity, size_t &outLen);
  size_t writeAssertionResponse(size_t recordIndex, const uint8_t clientDataHash[32], uint8_t *response,
                                size_t responseCapacity, bool includeCredentialCount, size_t credentialCount,
                                bool userVerified, bool userPresent);
  size_t writeAssertionFromIdentity(const AssertionIdentity &identity, const uint8_t clientDataHash[32],
                                    uint8_t *response, size_t responseCapacity, bool includeCredentialCount,
                                    size_t credentialCount, bool userVerified, bool userPresent, uint32_t signCount);
  // Stateless credential helpers (Phase 1 key-wrapping). See Ctap2.cpp.
  bool deriveStatelessKeyFromNonce(const uint8_t *nonce, const uint8_t rpIdHash[32], P256KeyPair &outKey);
  bool computeStatelessMac(const uint8_t *nonce, const uint8_t rpIdHash[32], uint8_t macOut[16]);
  bool buildStatelessCredentialId(const uint8_t rpIdHash[32], uint8_t outId[33], P256KeyPair &outKey);
  bool isStatelessCredentialId(const uint8_t *id, size_t len, const uint8_t rpIdHash[32]);
  bool deriveStatelessKey(const uint8_t *id, const uint8_t rpIdHash[32], P256KeyPair &outKey);
  size_t writeCredentialManagementRp(size_t recordIndex, uint8_t *response, size_t responseCapacity, bool includeTotal);
  size_t writeCredentialManagementCredential(size_t recordIndex, uint8_t *response, size_t responseCapacity,
                                             bool includeTotal);
  void writeRpEntity(CborWriter &writer, const CredentialRecord &record);
  void writeUserEntity(CborWriter &writer, const CredentialRecord &record);
  void writeCredentialDescriptor(CborWriter &writer, const CredentialRecord &record);
  void recordEvent(const char *kind, const char *cmd, const char *rp, const char *status, bool synthetic = false,
                   bool up = false, bool uv = false, const char *note = "", bool proof = false);
  void syncRecorderUx();

  CryptoProvider &crypto_;
  CredentialStore &store_;
  UserPresence &presence_;
  AmoledUx &ux_;
  LabRecorder &recorder_;
  MasterSecret masterSecret_;
  Preferences pinPrefs_;
  KeepaliveCallback keepalive_ = nullptr;
  void *keepaliveCtx_ = nullptr;
  volatile bool canceled_ = false;
  size_t assertionIndexes_[BuildConfig::kMaxCredentials] = {};
  size_t assertionCount_ = 0;
  size_t assertionNext_ = 0;
  uint8_t assertionClientDataHash_[32] = {};
  bool assertionUserVerified_ = false;
  size_t cmRpIndexes_[BuildConfig::kMaxCredentials] = {};
  size_t cmRpCount_ = 0;
  size_t cmRpNext_ = 0;
  size_t cmCredentialIndexes_[BuildConfig::kMaxCredentials] = {};
  size_t cmCredentialCount_ = 0;
  size_t cmCredentialNext_ = 0;
  P256KeyPair pinKeyAgreement_{};
  bool pinKeyReady_ = false;
  bool pinSet_ = false;
  uint8_t storedPinHash_[16] = {};
  uint8_t pinRetries_ = 8;
  uint8_t pinMismatches_ = 0;
  uint8_t pinUvAuthToken_[32] = {};
  uint32_t pinTokenPermissions_ = 0;
  char pinTokenRpId_[64] = {};
  bool pinTokenInUse_ = false;
};
