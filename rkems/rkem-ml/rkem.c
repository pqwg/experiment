//
// RKEM based on ML
//
#include "rkem.h"
#include "kem.h"

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


void rkem_init(struct rkem_buffer* buf) {(void)buf;}
void rkem_clear(struct rkem_buffer* buf) {(void)buf;}

int rkem_static_keygen(uint8_t pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
                       uint8_t sk[RKEM_STATIC_PRIVATE_KEY_BYTES]) {
  return 0 == PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}

int rkem_ephemeral_keygen(
    uint8_t pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    uint8_t sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    struct rkem_buffer* const buf) {
	(void)buf;

  return 0 == PQCLEAN_MLKEM512_CLEAN_crypto_kem_rkeypair(static_pk, pk, sk);
}

int rkem_encapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES], uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    const uint8_t ephemeral_pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    struct rkem_buffer* const buf) {
	(void)buf;

  return 0 == PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, static_pk, ephemeral_pk);
}

int rkem_decapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES],
    const uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_sk[RKEM_STATIC_PRIVATE_KEY_BYTES],
    const uint8_t ephemeral_sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    struct rkem_buffer* const buf) {
	(void)buf;

  return 0 == PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, static_sk, ephemeral_sk);
}
