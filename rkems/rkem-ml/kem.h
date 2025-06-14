#ifndef PQCLEAN_MLKEM512_CLEAN_KEM_H
#define PQCLEAN_MLKEM512_CLEAN_KEM_H
#include "params.h"

#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES           KYBER_SSBYTES

#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME "ML-KEM-512"

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_rkeypair_derand(const uint8_t *pk, uint8_t *rpk, uint8_t *rsk, const uint8_t *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_rkeypair(const uint8_t *pk, uint8_t *rpk, uint8_t *rsk);

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *rpk, const uint8_t *mu, const uint8_t *mur);

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *rpk);

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, const uint8_t *rsk);

#endif
