#ifndef PQWG_KEM
#define PQWG_KEM

#ifdef __KERNEL__
#include <crypto/curve25519.h>
#include <crypto/blake2s.h>

#else

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "curve25519.h"

#include <linux/types.h>
#include <sys/random.h>
typedef __u8 u8;
#include <stdbool.h>

#define __must_check
#endif


#define KEM_NAME "X25519"


#define MACRO_KEM_PUBLIC_KEY_SIZE 32

enum kem_lengths {
    KEM_PUBLIC_KEY_SIZE = CURVE25519_KEY_SIZE,
    KEM_PRIVATE_KEY_SIZE = CURVE25519_KEY_SIZE,
    KEM_SS_SIZE = 32,
    KEM_CIPHERTEXT_SIZE = CURVE25519_KEY_SIZE,
};


struct kem_buffer {
};

void kem_init(struct kem_buffer* buf);
void kem_clear(struct kem_buffer* buf);

#ifndef __KERNEL__
static inline void curve25519_generate_secret(u8 privatekey[KEM_PRIVATE_KEY_SIZE]) {
    if (!getrandom(privatekey, 32, 0)) {
		puts("getrandom failed");
		return;
	}
	curve25519_clamp_secret(privatekey);
}
#endif

static inline
bool __must_check kem_keygen(u8 publickey[KEM_PUBLIC_KEY_SIZE], u8 privatekey[KEM_PRIVATE_KEY_SIZE]) {
    curve25519_generate_secret(privatekey);
    bool result = true;
#ifdef __KERNEL__
    result = curve25519_generate_public(publickey, privatekey);
#else
    curve25519_generate_public(publickey, privatekey);
#endif
    return result;
}

#ifdef __KERNEL__
static inline
bool __must_check kem_encapsulate(
        u8 shared_secret[KEM_SS_SIZE], u8 ciphertext[KEM_CIPHERTEXT_SIZE],
        const u8 publickey[KEM_PUBLIC_KEY_SIZE],
	struct kem_buffer const* buf) {

    u8 sk[KEM_PRIVATE_KEY_SIZE];
    u8 dhkey[CURVE25519_KEY_SIZE];

    if (unlikely(!kem_keygen(ciphertext, sk))) {
        return false;
    }
    #if __KERNEL__
    if (unlikely(!curve25519(dhkey, sk, publickey))) {
        return false;
    }
    #else
    curve25519(dhkey, publickey, sk);
    #endif

    blake2s(shared_secret, ciphertext, dhkey, KEM_SS_SIZE, KEM_CIPHERTEXT_SIZE, CURVE25519_KEY_SIZE);

    return true;
}

static inline
bool __must_check kem_decapsulate(
        u8 shared_secret[static KEM_SS_SIZE],
        const u8 ciphertext[static KEM_CIPHERTEXT_SIZE],
        const u8 private_key[static KEM_PRIVATE_KEY_SIZE],
	struct kem_buffer const* buf) {
    u8 ss[CURVE25519_KEY_SIZE];
    if (unlikely(!curve25519(ss, private_key, ciphertext))) {
        return false;
    }

    blake2s(shared_secret, ciphertext, ss, KEM_SS_SIZE, KEM_CIPHERTEXT_SIZE, CURVE25519_KEY_SIZE);

    (void)buf;
    return true;
}
#endif



#endif
