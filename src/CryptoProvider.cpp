#include "CryptoProvider.h"

#include <esp_random.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <string.h>

void CryptoProvider::begin() {
  uint8_t warmup[32];
  randomBytes(warmup, sizeof(warmup));
  memset(warmup, 0, sizeof(warmup));
}

int CryptoProvider::rngCallback(void *ctx, unsigned char *out, size_t len) {
  (void)ctx;
  esp_fill_random(out, len);
  return 0;
}

bool CryptoProvider::randomBytes(uint8_t *out, size_t len) {
  if (!out) {
    return false;
  }
  esp_fill_random(out, len);
  return true;
}

bool CryptoProvider::sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  return mbedtls_sha256(data, len, out, 0) == 0;
}

bool CryptoProvider::hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md_hmac(info, key, keyLen, data, len, out) == 0;
}

bool CryptoProvider::hkdfSha256(const uint8_t *ikm, size_t ikmLen, const uint8_t *infoData, size_t infoLen,
                                uint8_t out[32]) {
  static const uint8_t kZeroSalt[32] = {};
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_hkdf(info, kZeroSalt, sizeof(kZeroSalt), ikm, ikmLen, infoData, infoLen, out, 32) == 0;
}

bool CryptoProvider::aes256CbcEncrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *plain, size_t len,
                                      uint8_t *out) {
  if (!plain || !out || len == 0 || (len % 16) != 0) return false;
  uint8_t ivCopy[16];
  memcpy(ivCopy, iv, sizeof(ivCopy));
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  const bool ok = mbedtls_aes_setkey_enc(&ctx, key, 256) == 0 &&
                  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, ivCopy, plain, out) == 0;
  mbedtls_aes_free(&ctx);
  memset(ivCopy, 0, sizeof(ivCopy));
  return ok;
}

bool CryptoProvider::aes256CbcDecrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *cipher, size_t len,
                                      uint8_t *out) {
  if (!cipher || !out || len == 0 || (len % 16) != 0) return false;
  uint8_t ivCopy[16];
  memcpy(ivCopy, iv, sizeof(ivCopy));
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  const bool ok = mbedtls_aes_setkey_dec(&ctx, key, 256) == 0 &&
                  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, ivCopy, cipher, out) == 0;
  mbedtls_aes_free(&ctx);
  memset(ivCopy, 0, sizeof(ivCopy));
  return ok;
}

bool CryptoProvider::generateP256(P256KeyPair &key) {
  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);

  bool ok = false;
  if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, rngCallback, nullptr) == 0 &&
      mbedtls_mpi_write_binary(&ctx.MBEDTLS_PRIVATE(d), key.privateKey, sizeof(key.privateKey)) == 0 &&
      mbedtls_mpi_write_binary(&ctx.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), key.publicX, sizeof(key.publicX)) == 0 &&
      mbedtls_mpi_write_binary(&ctx.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), key.publicY, sizeof(key.publicY)) == 0) {
    ok = true;
  }

  mbedtls_ecdsa_free(&ctx);
  return ok;
}

bool CryptoProvider::deriveP256FromSeed(const uint8_t seed[32], P256KeyPair &out) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  bool ok = false;
  if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
      mbedtls_mpi_read_binary(&d, seed, 32) == 0 &&
      mbedtls_mpi_mod_mpi(&d, &d, &group.N) == 0 &&
      mbedtls_mpi_cmp_int(&d, 0) != 0 &&
      mbedtls_ecp_mul(&group, &Q, &d, &group.G, rngCallback, nullptr) == 0 &&
      mbedtls_mpi_write_binary(&d, out.privateKey, sizeof(out.privateKey)) == 0 &&
      mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), out.publicX, sizeof(out.publicX)) == 0 &&
      mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), out.publicY, sizeof(out.publicY)) == 0) {
    ok = true;
  }

  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&group);
  return ok;
}

bool CryptoProvider::ecdhP256(const uint8_t privateKey[32], const uint8_t peerX[32], const uint8_t peerY[32],
                              uint8_t sharedSecret[32]) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point peer;
  mbedtls_mpi d;
  mbedtls_mpi z;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&peer);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&z);

  bool ok = false;
  if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
      mbedtls_mpi_read_binary(&d, privateKey, 32) == 0 &&
      mbedtls_mpi_read_binary(&peer.MBEDTLS_PRIVATE(X), peerX, 32) == 0 &&
      mbedtls_mpi_read_binary(&peer.MBEDTLS_PRIVATE(Y), peerY, 32) == 0 &&
      mbedtls_mpi_lset(&peer.MBEDTLS_PRIVATE(Z), 1) == 0 &&
      mbedtls_ecp_check_pubkey(&group, &peer) == 0 &&
      mbedtls_ecdh_compute_shared(&group, &z, &peer, &d, rngCallback, nullptr) == 0 &&
      mbedtls_mpi_write_binary(&z, sharedSecret, 32) == 0) {
    ok = true;
  }

  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&peer);
  mbedtls_ecp_group_free(&group);
  return ok;
}

bool CryptoProvider::signP256Der(const uint8_t privateKey[32], const uint8_t hash[32], uint8_t *sig, size_t sigCapacity, size_t &sigLen) {
  sigLen = 0;
  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);

  bool ok = false;
  if (mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1) == 0 &&
      mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(d), privateKey, 32) == 0 &&
      mbedtls_ecp_mul(&ctx.MBEDTLS_PRIVATE(grp), &ctx.MBEDTLS_PRIVATE(Q), &ctx.MBEDTLS_PRIVATE(d), &ctx.MBEDTLS_PRIVATE(grp).G, rngCallback, nullptr) == 0 &&
      mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, 32, sig, sigCapacity, &sigLen, rngCallback, nullptr) == 0) {
    ok = true;
  }

  mbedtls_ecdsa_free(&ctx);
  return ok;
}
