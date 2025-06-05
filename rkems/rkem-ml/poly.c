#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "reduce.h"
#include "symmetric.h"
#include "verify.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h> // For memset
#endif

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (of length KYBER_CTSTATICBYTES)
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_compress_static(uint8_t r[KYBER_CTSTATICBYTES], const poly *a) {
    unsigned int i, j;
    uint8_t t[8];

    for (i = 0; i < KYBER_N / 8; i++)
    {
        for (j = 0; j < 8; j++)
            t[j] = (((((int16_t)a->coeffs[8 * i + j]) * (1 << 3)) + KYBER_Q / 2) / KYBER_Q) & 7;

        r[0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
        r[1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);

        r += 3;
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_compress_ephemeral(uint8_t r[KYBER_CTEPHBYTES], const poly *a) {
    unsigned int i, j;
    uint8_t t[8];

    for (i = 0; i < KYBER_N / 8; i++)
    {
        for (j = 0; j < 8; j++)
            t[j] = ((((int16_t)a->coeffs[8 * i + j] * (1 << 7)) + KYBER_Q / 2) / KYBER_Q) & 127; // TODO: check why int instead of uint

        r[0] = (t[0] >> 0) | (t[1] << 7);
        r[1] = (t[1] >> 1) | (t[2] << 6);
        r[2] = (t[2] >> 2) | (t[3] << 5);
        r[3] = (t[3] >> 3) | (t[4] << 4);
        r[4] = (t[4] >> 4) | (t[5] << 3);
        r[5] = (t[5] >> 5) | (t[6] << 2);
        r[6] = (t[6] >> 6) | (t[7] << 1);

        r += 7;
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of PQCLEAN_MLKEM512_CLEAN_poly_compress
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_CTSTATICBYTES bytes)
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_decompress_static(poly *r, const uint8_t a[KYBER_CTSTATICBYTES]) {
    size_t i;

    unsigned int j;
    uint8_t t[8];
    for (i = 0; i < KYBER_N / 8; i++)
    {
        t[0] = (a[0] >> 0);
        t[1] = (a[0] >> 3);
        t[2] = (a[0] >> 6) | (a[1] << 2);
        t[3] = (a[1] >> 1);
        t[4] = (a[1] >> 4);
        t[5] = (a[1] >> 7) | (a[2] << 1);
        t[6] = (a[2] >> 2);
        t[7] = (a[2] >> 5);
        a += 3;

        for (j = 0; j < 8; j++)
            r->coeffs[8 * i + j] = ((uint32_t)(t[j] & 7) * KYBER_Q + 4) >> 3;
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_decompress_ephemeral(poly *r, const uint8_t a[KYBER_CTEPHBYTES]) {
    size_t i;

    unsigned int j;
    uint8_t t[8];
    for (i = 0; i < KYBER_N / 8; i++)
    {
        t[0] = (a[0] >> 0);
        t[1] = (a[0] >> 7) | (a[1] << 1);
        t[2] = (a[1] >> 6) | (a[2] << 2);
        t[3] = (a[2] >> 5) | (a[3] << 3);
        t[4] = (a[3] >> 4) | (a[4] << 4);
        t[5] = (a[4] >> 3) | (a[5] << 5);
        t[6] = (a[5] >> 2) | (a[6] << 6);
        t[7] = (a[6] >> 1);
        a += 7;

        for (j = 0; j < 8; j++)
            r->coeffs[8 * i + j] = ((uint32_t)(t[j] & 127) * KYBER_Q + 64) >> 7;
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_tobytes
*
* Description: Serialization of a polynomial, with 14 bits per coefficient
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYBYTES bytes)
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a) {
    size_t i, j;
    uint16_t t[4];

    for (i = 0; i < KYBER_N / 4; i++) {
        // map to positive standard representatives
        for (j = 0; j < 4; j++) {
            t[j] = a->coeffs[4 * i + j];
            t[j] += ((int16_t)t[j] >> 15) & KYBER_Q;
        }
        r[0] = (uint8_t)(t[0] >> 0);
        r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 6));
        r[2] = (uint8_t)(t[1] >> 2);
        r[3] = (uint8_t)((t[1] >> 10) | (t[2] << 4));
        r[4] = (uint8_t)(t[2] >> 4);
        r[5] = (uint8_t)((t[2] >> 12) | (t[3] << 2));
        r[6] = (uint8_t)(t[3] >> 6);
        r += 7;
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of PQCLEAN_MLKEM512_CLEAN_poly_tobytes
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of KYBER_POLYBYTES bytes)
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    size_t i, j;
    uint16_t t[4];
    for (i = 0; i < KYBER_N / 4; i++) {

        t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
        t[1] = (a[1] >> 6) | ((uint16_t)a[2] << 2) | ((uint16_t)a[3] << 10);
        t[2] = (a[3] >> 4) | ((uint16_t)a[4] << 4) | ((uint16_t)a[5] << 12);
        t[3] = (a[5] >> 2) | ((uint16_t)a[6] << 6);
        a += 7;

        for (j = 0; j < 4; j++)
            r->coeffs[4 * i + j] = (uint32_t)(t[j] & 16383);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]) {
    size_t i, j;

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = 0;
            PQCLEAN_MLKEM512_CLEAN_cmov_int16(r->coeffs + 8 * i + j, ((KYBER_Q + 1) / 2), (msg[i] >> j) & 1);
        }
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a) {
    unsigned int i, j;
    uint32_t t;

    for (i = 0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t  = a->coeffs[8 * i + j];
            t += ((int16_t)t >> 15) & KYBER_Q;
            t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
            // TODO: go back to magic trick
            // t <<= 1;
            // t += 1665;
            // t *= 80635;
            // t >>= 28;
            // t &= 1;
            msg[i] |= t << j;
        }
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_ntt(poly *r) {
    PQCLEAN_MLKEM512_CLEAN_ntt(r->coeffs);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(r);
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(poly *r) {
    PQCLEAN_MLKEM512_CLEAN_invntt(r->coeffs);
}

/**
 * @brief Multiplies two polynomials a(x) and b(x) in the ring Z_q / (x^n + 1).
 * Uses fixed-size arrays defined by KYBER_N and coefficients modulo KYBER_Q.
 * Performs reduction in-place, NO dynamic allocation.
 *
 * @param result Polynomial array (size KYBER_N) to store the result c(x) = a(x) * b(x).
 * @param a      Constant polynomial array (size KYBER_N) for the first operand.
 * @param b      Constant polynomial array (size KYBER_N) for the second operand.
 */
void PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
    PQCLEAN_MLKEM512_CLEAN_basemul(r->coeffs, a->coeffs, b->coeffs);
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_tomont(poly *r) {
    size_t i;
    const int16_t f = (1ULL << 32) % KYBER_Q;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = PQCLEAN_MLKEM512_CLEAN_montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_reduce(poly *r) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = PQCLEAN_MLKEM512_CLEAN_barrett_reduce(r->coeffs[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_add
*
* Description: Add two polynomials; no modular reduction is performed
*
* Arguments: - poly *r: pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_add(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_poly_sub
*
* Description: Subtract two polynomials; no modular reduction is performed
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_poly_sub(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}
