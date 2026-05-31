#pragma once

#include <Arduino.h>

struct P256KeyPair {
  uint8_t privateKey[32];
  uint8_t publicX[32];
  uint8_t publicY[32];
};

class CryptoProvider {
 public:
  void begin();
  bool randomBytes(uint8_t *out, size_t len);
  bool sha256(const uint8_t *data, size_t len, uint8_t out[32]);
  bool hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]);
  bool hkdfSha256(const uint8_t *ikm, size_t ikmLen, const uint8_t *info, size_t infoLen, uint8_t out[32]);
  bool aes256CbcEncrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *plain, size_t len, uint8_t *out);
  bool aes256CbcDecrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *cipher, size_t len, uint8_t *out);
  bool generateP256(P256KeyPair &key);
  bool ecdhP256(const uint8_t privateKey[32], const uint8_t peerX[32], const uint8_t peerY[32], uint8_t sharedSecret[32]);
  bool signP256Der(const uint8_t privateKey[32], const uint8_t hash[32], uint8_t *sig, size_t sigCapacity, size_t &sigLen);
  // Deterministically derive a P-256 keypair from a 32-byte seed: reduce the
  // seed mod the curve order n (rejecting 0) and compute Q = d*G. Used for
  // stateless credential key-wrapping, where the same (master, nonce, rpIdHash)
  // input must re-derive the identical key at registration and assertion.
  bool deriveP256FromSeed(const uint8_t seed[32], P256KeyPair &out);

 private:
  static int rngCallback(void *ctx, unsigned char *out, size_t len);
};
