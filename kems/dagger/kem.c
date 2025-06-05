#include "kem.h"
#include "saber.h"
#include "SABER_indcpa.h"
#include "randombytes.h"

#ifdef __KERNEL__
#else
#include <string.h>
#endif

void DNS(kem_init)(struct DNS(kem_buffer)* buf) {}
void DNS(kem_clear)(struct DNS(kem_buffer)* buf) {
#ifdef __KERNEL__
	memzero_explicit(buf, sizeof(struct DNS(kem_buffer)));
#else
	memset(buf, 0, sizeof(struct DNS(kem_buffer)));
#endif
}


bool __must_check DNS(kem_keygen)(
	u8 publickey[DNS(KEM_PUBLIC_KEY_SIZE)],
       	u8 privatekey[DNS(KEM_PRIVATE_KEY_SIZE)],
       	struct DNS(kem_buffer) *buf) {

	u8 coins[SABER_SEEDBYTES + SABER_COINBYTES];
	randombytes(coins, SABER_SEEDBYTES + SABER_NOISESEEDBYTES);

#ifdef __KERNEL__
	kernel_fpu_begin();
#endif
	indcpa_kem_keypair(publickey, privatekey, coins, coins + SABER_SEEDBYTES, &buf->buf);
#ifdef __KERNEL__
	kernel_fpu_end();
#endif

	return true;
}


bool __must_check DNS(kem_encapsulate)(
        u8 shared_secret[DNS(KEM_SS_SIZE)],
        u8 ciphertext[DNS(KEM_CIPHERTEXT_SIZE)],
        const u8 publickey[DNS(KEM_PUBLIC_KEY_SIZE)],
	struct DNS(kem_buffer) *buf) {

	u8 coins[SABER_KEYBYTES + SABER_NOISESEEDBYTES];
	randombytes(coins, SABER_KEYBYTES + SABER_NOISESEEDBYTES);

#ifdef __KERNEL__
	kernel_fpu_begin();
#endif
	saber_indcpa_enc(ciphertext, shared_secret, publickey, coins, &buf->buf);
#ifdef __KERNEL__
	kernel_fpu_end();
#endif

	return true;
}

bool __must_check DNS(kem_decapsulate)(
        u8 shared_secret[static DNS(KEM_SS_SIZE)],
        const u8 ciphertext[static DNS(KEM_CIPHERTEXT_SIZE)],
        const u8 private_key[static DNS(KEM_PRIVATE_KEY_SIZE)],
	struct DNS(kem_buffer) *buf) {

#ifdef __KERNEL__
	kernel_fpu_begin();
#endif
	saber_indcpa_dec(shared_secret, ciphertext, private_key, &buf->buf);
#ifdef __KERNEL__
	kernel_fpu_end();
#endif

	return true;
}
