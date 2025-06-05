#ifndef RKEM_H
#define RKEM_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

#include "params.h"

#define RKEM_NAME "RKEM-ML"

#define RKEM_STATIC_PUBLIC_KEY_BYTES KYBER_PUBLICKEYBYTES
#define RKEM_STATIC_PRIVATE_KEY_BYTES KYBER_SECRETKEYBYTES

#define RKEM_EPHEMERAL_PUBLIC_KEY_BYTES KYBER_RPUBLICKEYBYTES
#define RKEM_EPHEMERAL_PRIVATE_KEY_BYTES KYBER_RSECRETKEYBYTES

#define RKEM_CIPHERTEXT_BYTES KYBER_CIPHERTEXTBYTES
#define RKEM_SHARED_SECRET_BYTES KYBER_SSBYTES

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
