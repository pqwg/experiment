#ifndef PQWG_KEM_MC
#define PQWG_KEM_MC

#include "api.h"
#include "randombytes.h"

#include <linux/slab.h>
#include <asm/fpu/api.h>

#include "mcbuf.h"

#ifdef MCRKEM
#define NS(x) x
#else
#define NS(x) x
#endif

#define MACRO_KEM_PUBLIC_KEY_SIZE CRYPTO_PUBLICKEYBYTES

#define KEM_USES_BUFFER 1

enum NS(kem_lengths) {
    NS(KEM_PUBLIC_KEY_SIZE) = CRYPTO_PUBLICKEYBYTES,
    NS(KEM_PRIVATE_KEY_SIZE) = CRYPTO_SECRETKEYBYTES,
    NS(KEM_SS_SIZE) = CRYPTO_BYTES,
    NS(KEM_CIPHERTEXT_SIZE) = CRYPTO_CIPHERTEXTBYTES,
};


static inline
bool __must_check NS(kem_keygen)(u8 publickey[NS(KEM_PUBLIC_KEY_SIZE)], u8 privatekey[NS(KEM_PRIVATE_KEY_SIZE)]) {
    return false;
}

struct NS(kem_buffer) {
   struct mc_buffer buf;
};

void NS(kem_init)(struct NS(kem_buffer)* buf);
void NS(kem_clear)(struct NS(kem_buffer)* buf);

bool __must_check NS(kem_encapsulate)(
        u8 shared_secret[NS(KEM_SS_SIZE)],
        u8 ciphertext[NS(KEM_CIPHERTEXT_SIZE)],
        const u8 publickey[NS(KEM_PUBLIC_KEY_SIZE)],
	struct NS(kem_buffer) *buf);

bool __must_check NS(kem_decapsulate)(
        u8 shared_secret[static NS(KEM_SS_SIZE)],
        const u8 ciphertext[static NS(KEM_CIPHERTEXT_SIZE)],
        const u8 private_key[static NS(KEM_PRIVATE_KEY_SIZE)],
	struct NS(kem_buffer) *buf);

#endif
