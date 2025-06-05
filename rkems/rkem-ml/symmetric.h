#ifndef PQCLEAN_MLKEM512_CLEAN_SYMMETRIC_H
#define PQCLEAN_MLKEM512_CLEAN_SYMMETRIC_H
#include "fips202.h"
#include "params.h"

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

typedef shake128ctx xof_state;

void PQCLEAN_MLKEM512_CLEAN_kyber_shake128_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM512_CLEAN_kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM512_CLEAN_kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key1[KYBER_SYMBYTES], const uint8_t key2[KYBER_SYMBYTES], const uint8_t hash_pk[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM512_CLEAN_kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) shake128_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM512_CLEAN_kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY1, KEY2, HASHPK, INPUT) PQCLEAN_MLKEM512_CLEAN_kyber_shake256_rkprf(OUT, KEY1, KEY2, HASHPK, INPUT)

#endif /* SYMMETRIC_H */
