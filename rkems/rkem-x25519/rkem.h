#ifndef RKEM_H
#define RKEM_H

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

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#define RKEM_NAME "RKEM-X25519"

#define RKEM_STATIC_PUBLIC_KEY_BYTES 32
#define RKEM_STATIC_PRIVATE_KEY_BYTES 32

#define RKEM_EPHEMERAL_PUBLIC_KEY_BYTES 32
#define RKEM_EPHEMERAL_PRIVATE_KEY_BYTES 32

#define RKEM_CIPHERTEXT_BYTES 32
#define RKEM_SHARED_SECRET_BYTES 32

#define RKEM_SUCCESS 1
#define RKEM_FAILURE 0



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
