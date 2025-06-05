#ifndef PQCLEAN_MLKEM512_CLEAN_POLYVEC_H
#define PQCLEAN_MLKEM512_CLEAN_POLYVEC_H
#include "params.h"
#include "poly.h"


typedef struct {
    poly vec[KYBER_ELL];
} polyvecEll;
typedef struct {
    poly vec[KYBER_K];
} polyvecK;

void PQCLEAN_MLKEM512_CLEAN_polyvecEll_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvecEll *a);
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_decompress(polyvecEll *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

void PQCLEAN_MLKEM512_CLEAN_polyvecK_compress(uint8_t r[KYBER_RPK_COMPRESSEDBYTES], const polyvecK *a);
void PQCLEAN_MLKEM512_CLEAN_polyvecK_randdecompress(polyvecK *r, const uint8_t a[KYBER_RPK_COMPRESSEDBYTES]);

void PQCLEAN_MLKEM512_CLEAN_polyvecK_tobytes(uint8_t r[KYBER_POLYVECKBYTES], const polyvecK *a);
void PQCLEAN_MLKEM512_CLEAN_polyvecK_frombytes(polyvecK *r, const uint8_t a[KYBER_POLYVECKBYTES]);
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_tobytes(uint8_t r[KYBER_POLYVECELLBYTES], const polyvecEll *a);
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_frombytes(polyvecEll *r, const uint8_t a[KYBER_POLYVECELLBYTES]);

void PQCLEAN_MLKEM512_CLEAN_polyvecEll_ntt(polyvecEll *r);
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_invntt_tomont(polyvecEll *r);
void PQCLEAN_MLKEM512_CLEAN_polyvecK_ntt(polyvecK *r);
void PQCLEAN_MLKEM512_CLEAN_polyvecK_invntt_tomont(polyvecK *r);

void PQCLEAN_MLKEM512_CLEAN_polyvecEll_basemul_acc_montgomery(poly *r, const polyvecEll *a, const polyvecEll *b);
void PQCLEAN_MLKEM512_CLEAN_polyvecK_basemul_acc_montgomery(poly *r, const polyvecK *a, const polyvecK *b);

void PQCLEAN_MLKEM512_CLEAN_polyvecEll_reduce(polyvecEll *r);
void PQCLEAN_MLKEM512_CLEAN_polyvecK_reduce(polyvecK *r);

void PQCLEAN_MLKEM512_CLEAN_polyvecEll_add(polyvecEll *r, const polyvecEll *a, const polyvecEll *b);
void PQCLEAN_MLKEM512_CLEAN_polyvecK_add(polyvecK *r, const polyvecK *a, const polyvecK *b);

#endif
