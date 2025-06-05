#ifndef PQCLEAN_MLKEM512_CLEAN_POLY_H
#define PQCLEAN_MLKEM512_CLEAN_POLY_H
#include "params.h"

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

void PQCLEAN_MLKEM512_CLEAN_poly_compress_static(uint8_t r[KYBER_CTSTATICBYTES], const poly *a);
void PQCLEAN_MLKEM512_CLEAN_poly_decompress_static(poly *r, const uint8_t a[KYBER_CTSTATICBYTES]);
void PQCLEAN_MLKEM512_CLEAN_poly_compress_ephemeral(uint8_t r[KYBER_CTEPHBYTES], const poly *a);
void PQCLEAN_MLKEM512_CLEAN_poly_decompress_ephemeral(poly *r, const uint8_t a[KYBER_CTEPHBYTES]);

void PQCLEAN_MLKEM512_CLEAN_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
void PQCLEAN_MLKEM512_CLEAN_poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

void PQCLEAN_MLKEM512_CLEAN_poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
void PQCLEAN_MLKEM512_CLEAN_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a);

void PQCLEAN_MLKEM512_CLEAN_poly_ntt(poly *r);
void PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(poly *r);
void PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void PQCLEAN_MLKEM512_CLEAN_poly_tomont(poly *r);

void PQCLEAN_MLKEM512_CLEAN_poly_reduce(poly *r);

void PQCLEAN_MLKEM512_CLEAN_poly_add(poly *r, const poly *a, const poly *b);
void PQCLEAN_MLKEM512_CLEAN_poly_sub(poly *r, const poly *a, const poly *b);

#endif
