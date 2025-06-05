#ifndef SABER_INDCPA_H
#define SABER_INDCPA_H

#include "ephemeral_buf.h"

void indcpa_kem_keypair(unsigned char *pk, unsigned char *sk,
                        unsigned char seed[SABER_SEEDBYTES],
                        unsigned char noiseseed[SABER_COINBYTES],
                        struct eph_buffer* const ebuf);

void indcpa_kem_enc(unsigned char *message, unsigned char *noiseseed,
                    const unsigned char *pk, unsigned char *ciphertext,
                    struct eph_buffer* const ebuf);

void indcpa_kem_dec(const unsigned char *sk,
                    const unsigned char *ciphertext,
                    unsigned char *message_dec, struct eph_buffer* const ebuf);

#endif
