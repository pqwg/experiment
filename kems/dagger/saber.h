#ifndef SABER_KEM_H_
#define SABER_KEM_H_

#include "ephemeral_buf.h"

void saber_indcpa_enc(unsigned char* ct, unsigned char *ss,
                      const unsigned char *pk,
                      unsigned char coins[SABER_KEYBYTES + SABER_NOISESEEDBYTES],
                      struct eph_buffer* const ebuf);

void saber_indcpa_dec(unsigned char *ss, const unsigned char *ct,
                      const unsigned char *sk, struct eph_buffer* const ebuf);

#endif // SABER_KEM_H_
