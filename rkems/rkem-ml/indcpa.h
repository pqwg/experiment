#ifndef PQCLEAN_MLKEM512_CLEAN_INDCPA_H
#define PQCLEAN_MLKEM512_CLEAN_INDCPA_H

#include "params.h"
#include "polyvec.h"

void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvecEll *a, const uint8_t seed[KYBER_SYMBYTES]);
void PQCLEAN_MLKEM512_CLEAN_gen_matrix_t(polyvecK *a, const uint8_t seed[KYBER_SYMBYTES]);

void PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]);

void PQCLEAN_MLKEM512_CLEAN_indcpa_rkeypair_derand(const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t rpk[KYBER_INDCPA_RPUBLICKEYBYTES],
        uint8_t rsk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]);

void PQCLEAN_MLKEM512_CLEAN_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t mu[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t mur[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                       const uint8_t rpk[KYBER_INDCPA_RPUBLICKEYBYTES],
                                       const uint8_t coins[KYBER_SYMBYTES]);

void PQCLEAN_MLKEM512_CLEAN_indcpa_dec(uint8_t mu[KYBER_INDCPA_MSGBYTES],
                                       uint8_t mur[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                                       const uint8_t rsk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
