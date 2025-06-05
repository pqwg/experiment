#ifndef OPERATIONS_H
#define OPERATIONS_H

#include "mcbuf.h"
#include "encrypt.h"

int crypto_kem_mceliece460896_avx_enc(
       unsigned char *c,
       unsigned char *key,
       const unsigned char *pk,
       const unsigned char key1[TWISTED_PRF_KEY_LEN],
       const unsigned char key2[TWISTED_PRF_KEY_LEN],
       struct mc_buffer* const buf
);

int crypto_kem_mceliece460896_avx_dec(
       unsigned char *key,
       const unsigned char *c,
       const unsigned char *sk,
       struct mc_buffer* const buf
);

#endif

