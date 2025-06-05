#include "kem.h"
#include "randombytes.h"
#include "crypto_kem_mceliece.h"

void NS(kem_init)(struct NS(kem_buffer)* buf) {
   init_mcbuf(&buf->buf);
}

void NS(kem_clear)(struct NS(kem_buffer)* buf) {
   clear_mcbuf(&buf->buf);
}


bool __must_check NS(kem_encapsulate)(
        u8 shared_secret[NS(KEM_SS_SIZE)],
        u8 ciphertext[NS(KEM_CIPHERTEXT_SIZE)],
        const u8 publickey[NS(KEM_PUBLIC_KEY_SIZE)],
	struct NS(kem_buffer) *buf) {

    u8 random[crypto_kem_twisted_prf_BYTES * 2];
    randombytes(random, crypto_kem_twisted_prf_BYTES * 2);

    kernel_fpu_begin();
    int result = crypto_kem_mceliece_enc(ciphertext, shared_secret, publickey, random, random + crypto_kem_twisted_prf_BYTES, &buf->buf);
    kernel_fpu_end();
    return 0 == result;
}


bool __must_check NS(kem_decapsulate)(
        u8 shared_secret[static NS(KEM_SS_SIZE)],
        const u8 ciphertext[static NS(KEM_CIPHERTEXT_SIZE)],
        const u8 private_key[static NS(KEM_PRIVATE_KEY_SIZE)],
	struct NS(kem_buffer) *buf) {

    kernel_fpu_begin();
    int result = crypto_kem_mceliece_dec(shared_secret, ciphertext, private_key, &buf->buf);
    kernel_fpu_end();
    return 0 == result;

}


