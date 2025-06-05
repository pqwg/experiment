//
// RKEM based on Dagger + McEliece
//
#include "rkem.h"
#include "mceliece/fips202.h"

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
	(void)buf;
}
  
void rkem_clear(struct rkem_buffer* buf) {
	(void)buf;
}

// not supported by this McEliece implementation
int rkem_static_keygen(uint8_t pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
                       uint8_t sk[RKEM_STATIC_PRIVATE_KEY_BYTES]){
	return kem_keygen(pk, sk);
}
