#ifndef crypto_kem_mceliece_H
#define crypto_kem_mceliece_H

#include "mcbuf.h"

#define crypto_kem_mceliece460896_avx_PUBLICKEYBYTES 524160
#define crypto_kem_mceliece460896_avx_SECRETKEYBYTES 13568
#define crypto_kem_mceliece460896_avx_CIPHERTEXTBYTES 188
#define crypto_kem_mceliece460896_avx_BYTES 32
#define crypto_kem_twisted_prf_BYTES 32
 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece460896_avx_enc(unsigned char *,unsigned char *,
                        const unsigned char *,
                        const unsigned char k1[crypto_kem_twisted_prf_BYTES],
                        const unsigned char k2[crypto_kem_twisted_prf_BYTES],
			struct mc_buffer* const buf);

extern int crypto_kem_mceliece460896_avx_dec(unsigned char *,const unsigned char *,
                                             const unsigned char *,
                                             struct mc_buffer* const buf);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece460896_enc crypto_kem_mceliece460896_avx_enc
#define crypto_kem_mceliece460896_dec crypto_kem_mceliece460896_avx_dec
#define crypto_kem_mceliece460896_PUBLICKEYBYTES crypto_kem_mceliece460896_avx_PUBLICKEYBYTES
#define crypto_kem_mceliece460896_SECRETKEYBYTES crypto_kem_mceliece460896_avx_SECRETKEYBYTES
#define crypto_kem_mceliece460896_BYTES crypto_kem_mceliece460896_avx_BYTES
#define crypto_kem_mceliece460896_CIPHERTEXTBYTES crypto_kem_mceliece460896_avx_CIPHERTEXTBYTES

#define crypto_kem_mceliece_enc crypto_kem_mceliece460896_avx_enc
#define crypto_kem_mceliece_dec crypto_kem_mceliece460896_avx_dec
#define crypto_kem_mceliece_PUBLICKEYBYTES crypto_kem_mceliece460896_avx_PUBLICKEYBYTES
#define crypto_kem_mceliece_SECRETKEYBYTES crypto_kem_mceliece460896_avx_SECRETKEYBYTES
#define crypto_kem_mceliece_BYTES crypto_kem_mceliece460896_avx_BYTES
#define crypto_kem_mceliece_CIPHERTEXTBYTES crypto_kem_mceliece460896_avx_CIPHERTEXTBYTES

#endif
