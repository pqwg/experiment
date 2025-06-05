#ifndef RKEM_H
#define RKEM_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#include "mceliece/api.h"
#include "mceliece/kem.h"

#define RKEM_NAME "RKEM-DAGGER-MCELIECE"

#define RKEM_STATIC_PUBLIC_KEY_BYTES (PQCLEAN_MCELIECE460896_VEC_CRYPTO_PUBLICKEYBYTES)
#define RKEM_STATIC_PRIVATE_KEY_BYTES (PQCLEAN_MCELIECE460896_VEC_CRYPTO_SECRETKEYBYTES)

#define RKEM_EPHEMERAL_PUBLIC_KEY_BYTES 999
#define RKEM_EPHEMERAL_PRIVATE_KEY_BYTES 999

#define RKEM_CIPHERTEXT_BYTES (PQCLEAN_MCELIECE460896_VEC_CRYPTO_CIPHERTEXTBYTES)
#define RKEM_SHARED_SECRET_BYTES 32

#define RKEM_SUCCESS true
#define RKEM_FAILURE false


struct rkem_buffer {
};

void rkem_init(struct rkem_buffer* buf);
void rkem_clear(struct rkem_buffer* buf);



size_t rkem_static_public_key_bytes(void);
size_t rkem_ephemeral_public_key_bytes(void);
size_t rkem_static_private_key_bytes(void);
size_t rkem_ephemeral_private_key_bytes(void);
size_t rkem_ciphertext_bytes(void);
size_t rkem_shared_secret_bytes(void);

int rkem_static_keygen(uint8_t pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
                       uint8_t sk[RKEM_STATIC_PRIVATE_KEY_BYTES]);
		       

#endif
