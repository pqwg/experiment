//
// RKEM based on X25519
//
// This is a mock implementation, that computes the following:
//
// Note that this implemenation *does not* necessarily meet RKEM security
// guarantees!
//
//  * Keygen: x25519 vanilla
//  * encapsulation(pk1, pk2):
//      1. generate ephemeral point e, g^e
//      2. ss = SHAKE256(pk1^e || pk2^e)
//      3. ct = g^e
//  * decaps follows equivalently:
//      1. ct = g^e
//      2. ss = SHAKE256(ct^sk1 || ct^sk2)

#include "fips202.h"
#include "randombytes.h"
#include "rkem.h"

size_t rkem_static_public_key_bytes(void) {
  return RKEM_STATIC_PUBLIC_KEY_BYTES;
}

size_t rkem_ephemeral_public_key_bytes(void) {
  return RKEM_EPHEMERAL_PUBLIC_KEY_BYTES;
}

size_t rkem_static_private_key_bytes(void) {
  return RKEM_STATIC_PRIVATE_KEY_BYTES;
}

size_t rkem_ephemeral_private_key_bytes(void) {
  return RKEM_EPHEMERAL_PRIVATE_KEY_BYTES;
}

size_t rkem_ciphertext_bytes(void) { return RKEM_CIPHERTEXT_BYTES; }
size_t rkem_shared_secret_bytes(void) { return RKEM_SHARED_SECRET_BYTES; }

extern int curve25519_donna(uint8_t *secret, const uint8_t *public,
                            const uint8_t *basepoint);

static void x25519_keygen(uint8_t *sk) {
  randombytes(sk, RKEM_STATIC_PRIVATE_KEY_BYTES);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
}

void rkem_init(struct rkem_buffer* buf) {(void)buf;}
void rkem_clear(struct rkem_buffer* buf) {(void)buf;}

int rkem_static_keygen(uint8_t pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
                       uint8_t sk[RKEM_STATIC_PRIVATE_KEY_BYTES]) {
  static const uint8_t basepoint[32] = {9};

  x25519_keygen(sk);
  curve25519_donna(pk, sk, basepoint);
  return RKEM_SUCCESS;
}

int rkem_ephemeral_keygen(
    uint8_t pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    uint8_t sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    struct rkem_buffer* const buf) {
  (void)static_pk;
  (void)buf;
  return rkem_static_keygen(pk, sk);
}

int rkem_encapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES], uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    const uint8_t ephemeral_pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    struct rkem_buffer* const buf) {
	(void)buf;

  uint8_t ct_secret[32] = {0};
  rkem_static_keygen(ct, ct_secret);
  uint8_t ss_internal[64] = {0};
  curve25519_donna(ss_internal, ct_secret, static_pk);
  curve25519_donna(ss_internal + 32, ct_secret, ephemeral_pk);

  shake256(ss, RKEM_SHARED_SECRET_BYTES, ss_internal, 64);
  return RKEM_SUCCESS;
}

int rkem_decapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES],
    const uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_sk[RKEM_STATIC_PRIVATE_KEY_BYTES],
    const uint8_t ephemeral_sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    struct rkem_buffer* const buf) {
	(void)buf;

  uint8_t ss_internal[64] = {0};

  curve25519_donna(ss_internal, static_sk, ct);
  curve25519_donna(ss_internal + 32, ephemeral_sk, ct);
  shake256(ss, RKEM_SHARED_SECRET_BYTES, ss_internal, 64);

  return RKEM_SUCCESS;
}
