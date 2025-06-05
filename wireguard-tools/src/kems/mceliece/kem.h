#ifndef PQWG_KEM
#define PQWG_KEM

#ifdef __KERNEL__
#include <crypto/curve25519.h>
#include <crypto/blake2s.h>
#else
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>


#include <linux/types.h>
#include <sys/random.h>
typedef __u8 u8;
#include <stdbool.h>

#include "api.h"

#define KEM_NAME PQCLEAN_MCELIECE460896_VEC_CRYPTO_ALGNAME

#define __must_check
#endif

enum kem_lengths {
    KEM_PUBLIC_KEY_SIZE = PQCLEAN_MCELIECE460896_VEC_CRYPTO_PUBLICKEYBYTES,
    KEM_PRIVATE_KEY_SIZE = PQCLEAN_MCELIECE460896_VEC_CRYPTO_SECRETKEYBYTES,
    KEM_SS_SIZE = PQCLEAN_MCELIECE460896_VEC_CRYPTO_BYTES,
    KEM_CIPHERTEXT_SIZE = PQCLEAN_MCELIECE460896_VEC_CRYPTO_CIPHERTEXTBYTES,
};


struct kem_buffer {
};

static inline void kem_init(struct kem_buffer* buf) {
  (void)buf;
}

static inline void kem_clear(struct kem_buffer* buf) {
  (void)buf;
}

static inline
bool __must_check kem_keygen(u8 publickey[KEM_PUBLIC_KEY_SIZE], u8 privatekey[KEM_PRIVATE_KEY_SIZE]) {
    int result = PQCLEAN_MCELIECE460896_VEC_crypto_kem_keypair(publickey, privatekey);
    return result == 0;
}



#endif
