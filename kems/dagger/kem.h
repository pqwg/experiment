#ifndef PQWG_KEM_DAG
#define PQWG_KEM_DAG

#include "ephemeral_buf.h"
#include "SABER_params.h"

#ifdef __KERNEL__
#include <asm/fpu/api.h>
#include <linux/string.h>
#else
#define __must_check
#include <stdbool.h>
#include <string.h>
#define u8 uint8_t
#endif

#ifdef MCRKEM
#define DNS(x) dagger_ ## x
#else
#define DNS(x) x
#define MACRO_KEM_PUBLIC_KEY_SIZE SABER_PUBLICKEYBYTES
#endif

enum DNS(kem_lengths) {
    DNS(KEM_PUBLIC_KEY_SIZE) = SABER_PUBLICKEYBYTES,
    DNS(KEM_PRIVATE_KEY_SIZE) = SABER_SECRETKEYBYTES,
    DNS(KEM_SS_SIZE) = SABER_KEYBYTES,
    DNS(KEM_CIPHERTEXT_SIZE) = SABER_CIPHERTEXTBYTES,
};

struct DNS(kem_buffer) {
   struct eph_buffer buf;
};



bool __must_check DNS(kem_keygen)(
	u8 publickey[DNS(KEM_PUBLIC_KEY_SIZE)],
       	u8 privatekey[DNS(KEM_PRIVATE_KEY_SIZE)],
       	struct DNS(kem_buffer) *buf);

void DNS(kem_init)(struct DNS(kem_buffer)* buf);
void DNS(kem_clear)(struct DNS(kem_buffer)* buf);

bool __must_check DNS(kem_encapsulate)(
        u8 shared_secret[DNS(KEM_SS_SIZE)],
        u8 ciphertext[DNS(KEM_CIPHERTEXT_SIZE)],
        const u8 publickey[DNS(KEM_PUBLIC_KEY_SIZE)],
	struct DNS(kem_buffer) *buf);

bool __must_check DNS(kem_decapsulate)(
        u8 shared_secret[static DNS(KEM_SS_SIZE)],
        const u8 ciphertext[static DNS(KEM_CIPHERTEXT_SIZE)],
        const u8 private_key[static DNS(KEM_PRIVATE_KEY_SIZE)],
	struct DNS(kem_buffer) *buf);


#endif
