//
// RKEM based on Dagger + McEliece
//
#include "rkem.h"
#include "dagger/fips202.h"

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


void rkem_init(struct rkem_buffer* buf) {
  dagger_kem_init(&buf->dagbuf);
  kem_init(&buf->mcbuf);
}
  
void rkem_clear(struct rkem_buffer* buf) {
	dagger_kem_clear(&buf->dagbuf);
	kem_clear(&buf->mcbuf);
}

// not supported by this McEliece implementation
int rkem_static_keygen(uint8_t pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
                       uint8_t sk[RKEM_STATIC_PRIVATE_KEY_BYTES]) {
	(void)pk;(void)sk;
	return 0;
}

int rkem_ephemeral_keygen(
    uint8_t pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    uint8_t sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    struct rkem_buffer *buf) {
	
    return dagger_kem_keygen(pk, sk, &buf->dagbuf);
}

int rkem_encapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES], uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    const uint8_t ephemeral_pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    struct rkem_buffer *buf) {
 
    u8 ss1[32 + 32] = {};
    memset(ct, 0, RKEM_CIPHERTEXT_BYTES);

    int result = dagger_kem_encapsulate(ss1, ct, ephemeral_pk, &buf->dagbuf);
    result &= kem_encapsulate(ss1 + 32, ct + SABER_CIPHERTEXTBYTES, static_pk, &buf->mcbuf);

    sha3_256(ss, ss1, 32 + 32);

    return result;
}

int rkem_decapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES],
    const uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_sk[RKEM_STATIC_PRIVATE_KEY_BYTES],
    const uint8_t ephemeral_sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    struct rkem_buffer *buf) {

    u8 ss1[64] = {};

    int result = dagger_kem_decapsulate(ss1, ct, ephemeral_sk, &buf->dagbuf); 
    result &= kem_decapsulate(ss1 + dagger_KEM_SS_SIZE, ct + dagger_KEM_CIPHERTEXT_SIZE, static_sk, &buf->mcbuf);

    sha3_256(ss, ss1, 64);
    return result;
}
