#ifndef RKEM_H
#define RKEM_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#include "dagger/kem.h"

#include "mceliece/kem.h"

#define RKEM_NAME "RKEM-DAGGER-MCELIECE"

#define RKEM_STATIC_PUBLIC_KEY_BYTES (CRYPTO_PUBLICKEYBYTES)
#define RKEM_STATIC_PRIVATE_KEY_BYTES (CRYPTO_SECRETKEYBYTES)

#define RKEM_EPHEMERAL_PUBLIC_KEY_BYTES (SABER_PUBLICKEYBYTES)
#define RKEM_EPHEMERAL_PRIVATE_KEY_BYTES (SABER_SECRETKEYBYTES)

#define RKEM_CIPHERTEXT_BYTES (SABER_CIPHERTEXTBYTES + CRYPTO_CIPHERTEXTBYTES)
#define RKEM_SHARED_SECRET_BYTES 32

#define RKEM_SUCCESS true
#define RKEM_FAILURE false


struct rkem_buffer {
   struct dagger_kem_buffer dagbuf;
   struct kem_buffer mcbuf;
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

int rkem_ephemeral_keygen(
    uint8_t pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    uint8_t sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    struct rkem_buffer* const buf);

int rkem_encapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES], uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_pk[RKEM_STATIC_PUBLIC_KEY_BYTES],
    const uint8_t ephemeral_pk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES],
    struct rkem_buffer* const buf);

int rkem_decapsulate(
    uint8_t ss[RKEM_SHARED_SECRET_BYTES],
    const uint8_t ct[RKEM_CIPHERTEXT_BYTES],
    const uint8_t static_sk[RKEM_STATIC_PRIVATE_KEY_BYTES],
    const uint8_t ephemeral_sk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES],
    struct rkem_buffer* const buf);

#endif
