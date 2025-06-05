#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvecEll *a) {
    unsigned int i, j, k;

    uint16_t t[2];
    for (i = 0; i < KYBER_ELL; i++) {
        for (j = 0; j < KYBER_N / 2; j++)
        {
            for (k = 0; k < 2; k++) {
                t[k] = ((((int32_t)a->vec[i].coeffs[2 * j + k] * (1 << 12)) + KYBER_Q / 2) / KYBER_Q) & 4095;
            }
            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 4));
            r[2] = (uint8_t)(t[1] >> 4);
            r += 3;
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_polyvecK_compress(uint8_t r[KYBER_RPK_COMPRESSEDBYTES], const polyvecK *a) {
    unsigned int i, j, k;

    uint16_t t[8];
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 8; j++)
        {
            for (k = 0; k < 8; k++)
                t[k] = (((((int32_t)a->vec[i].coeffs[8 * j + k]) * (1 << 9)) + KYBER_Q / 2) / KYBER_Q) & 511; 
            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 1));
            r[2] = (uint8_t)((t[1] >> 7) | (t[2] << 2));
            r[3] = (uint8_t)((t[2] >> 6) | (t[3] << 3));
            r[4] = (uint8_t)((t[3] >> 5) | (t[4] << 4));
            r[5] = (uint8_t)((t[4] >> 4) | (t[5] << 5));
            r[6] = (uint8_t)((t[5] >> 3) | (t[6] << 6));
            r[7] = (uint8_t)((t[6] >> 2) | (t[7] << 7));
            r[8] = (uint8_t)(t[7] >> 1);
            r += 9;
        }
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of PQCLEAN_MLKEM512_CLEAN_polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_decompress(polyvecEll *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]) {
    unsigned int i, j, k;

    uint16_t t[2];
    for (i = 0; i < KYBER_ELL; i++) {
        for (j = 0; j < KYBER_N / 2; j++) {
            t[0] = ((a[0] >> 0) | ((uint16_t)a[1] << 8)) & 0xFFF;
            t[1] = ((a[1] >> 4) | ((uint16_t)a[2] << 4)) & 0xFFF;
            a += 3;

            for (k = 0; k < 2; k++) {
                r->vec[i].coeffs[2 * j + k] = ((uint32_t)(t[k] & 4095) * KYBER_Q + 2048) >> 12;
            }
        }
    }
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t v[8];

    ctr = pos = 0;
    while (ctr < len && pos + 5 <= buflen) {
        v[0] = (buf[pos + 0] >> 0);
        v[1] = (buf[pos + 0] >> 5) | (buf[pos + 1] << 3);
        v[2] = (buf[pos + 1] >> 2);
        v[3] = (buf[pos + 1] >> 7) | (buf[pos + 2] << 1);
        v[4] = (buf[pos + 2] >> 4) | (buf[pos + 3] << 4);
        v[5] = (buf[pos + 3] >> 1);
        v[6] = (buf[pos + 3] >> 6) | (buf[pos + 4] << 2);
        v[7] = (buf[pos + 4] >> 3);
        pos += 5;

        for (int i = 0; i < 8; i++) {
            v[i] &= 0x1F; // keep only 5 bits
            if (ctr >= len) {
                break;
            }

            // When the decompressed bits are equal to special_bits, then 
            // the lower bits are uniformly sampled in [-11, 10]
            // otherwise, in [-10, 10]
            const uint16_t special_bits = ((int32_t)256 * KYBER_Q + 256) >> 9;
            if (r[ctr] == special_bits && v[i] < 22) {
                r[ctr++] -= v[i] - 11;
            } else if (v[i] < 21) {
                r[ctr++] -= v[i] - 10;
            }
        }
    }

    return ctr;
}

/*************************************************
 * Name:        PQCLEAN_MLKEM512_CLEAN_gen_matrix
 *
 * Description: Deterministically generate matrix A (or the transpose of A)
 *              from a seed. Entries of the matrix are polynomials that look
 *              uniformly random. Performs rejection sampling on output of
 *              a XOF
 *
 * Arguments:   - polyvec *a: pointer to ouptput matrix A
 *              - const uint8_t *seed: pointer to input seed
 *              - int transposed: boolean deciding whether A or A^T is generated
 **************************************************/

#define GEN_LOWBITS_NBLOCKS ((12 * KYBER_N * KYBER_K / 8 * (1 << 5) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES)

// Not static for benchmarking
static void gen_lowbits(poly *a, const uint8_t seed[KYBER_SYMBYTES], uint8_t i)
{
    unsigned int ctr;
    unsigned int buflen;
    uint8_t buf[GEN_LOWBITS_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    xof_absorb(&state, seed, 'l', i);

    xof_squeezeblocks(buf, GEN_LOWBITS_NBLOCKS, &state);
    buflen = GEN_LOWBITS_NBLOCKS * XOF_BLOCKBYTES;
    ctr = rej_uniform(a->coeffs, KYBER_N, buf, buflen);

    while (ctr < KYBER_N)
    {
        xof_squeezeblocks(buf, 1, &state);
        buflen = XOF_BLOCKBYTES;
        ctr += rej_uniform(a->coeffs + ctr, KYBER_N - ctr, buf, buflen);
    }
    xof_ctx_release(&state);
}

void PQCLEAN_MLKEM512_CLEAN_polyvecK_randdecompress(polyvecK *r, const uint8_t a[KYBER_RPK_COMPRESSEDBYTES]) {
    unsigned int i, j, k;
    uint8_t h_rpk[KYBER_SYMBYTES];
    hash_h(h_rpk, a, KYBER_RPK_COMPRESSEDBYTES);

    uint16_t t[256];
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 8; j++) {
            t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
            t[1] = (a[1] >> 1) | ((uint16_t)a[2] << 7);
            t[2] = (a[2] >> 2) | ((uint16_t)a[3] << 6);
            t[3] = (a[3] >> 3) | ((uint16_t)a[4] << 5);
            t[4] = (a[4] >> 4) | ((uint16_t)a[5] << 4);
            t[5] = (a[5] >> 5) | ((uint16_t)a[6] << 3);
            t[6] = (a[6] >> 6) | ((uint16_t)a[7] << 2);
            t[7] = (a[7] >> 7) | ((uint16_t)a[8] << 1);

            a += 9;

            for (k = 0; k < 8; k++)
                r->vec[i].coeffs[8 * j + k] = ((uint32_t)(t[k] & 511) * KYBER_Q + 256) >> 9;
        }

        gen_lowbits(&r->vec[i], h_rpk, i);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_tobytes(uint8_t r[KYBER_POLYVECELLBYTES], const polyvecEll *a) {
    unsigned int i;
    for (i = 0; i < KYBER_ELL; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvecK_tobytes(uint8_t r[KYBER_POLYVECKBYTES], const polyvecK *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
*                                  (of length KYBER_POLYVECBYTES)
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_frombytes(polyvecEll *r, const uint8_t a[KYBER_POLYVECELLBYTES]) {
    unsigned int i;
    for (i = 0; i < KYBER_ELL; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvecK_frombytes(polyvecK *r, const uint8_t a[KYBER_POLYVECKBYTES]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_ntt(polyvecEll *r) {
    unsigned int i;
    for (i = 0; i < KYBER_ELL; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_ntt(&r->vec[i]);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvecK_ntt(polyvecK *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_ntt(&r->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_invntt_tomont(polyvecEll *r) {
    unsigned int i;
    for (i = 0; i < KYBER_ELL; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&r->vec[i]);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvecK_invntt_tomont(polyvecK *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&r->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_basemul_acc_montgomery(poly *r, const polyvecEll *a, const polyvecEll *b) {
    unsigned int i;
    poly t;

    PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < KYBER_ELL; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        PQCLEAN_MLKEM512_CLEAN_poly_add(r, r, &t);
    }

    PQCLEAN_MLKEM512_CLEAN_poly_reduce(r);
}
void PQCLEAN_MLKEM512_CLEAN_polyvecK_basemul_acc_montgomery(poly *r, const polyvecK *a, const polyvecK *b) {
    unsigned int i;
    poly t;

    PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        PQCLEAN_MLKEM512_CLEAN_poly_add(r, r, &t);
    }

    PQCLEAN_MLKEM512_CLEAN_poly_reduce(r);
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - polyvec *r: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_reduce(polyvecEll *r) {
    unsigned int i;
    for (i = 0; i < KYBER_ELL; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_reduce(&r->vec[i]);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvecK_reduce(polyvecK *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_reduce(&r->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r: pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_polyvecEll_add(polyvecEll *r, const polyvecEll *a, const polyvecEll *b) {
    unsigned int i;
    for (i = 0; i < KYBER_ELL; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvecK_add(polyvecK *r, const polyvecK *a, const polyvecK *b) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
