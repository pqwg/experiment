/*
  This file is for functions related to 256-bit vectors
  including functions for bitsliced field operations
*/

#ifndef VEC256_H
#define VEC256_H

#include "vec128.h"

#include <immintrin.h>

typedef __m256i vec256;

#define vec256_set1_16b(a) _mm256_set1_epi16((a))
#define vec256_setzero() _mm256_setzero_si256()
#define vec256_set4x(a0, a1, a2, a3) _mm256_set_epi64x(a3, a2, a1, a0)

#define vec256_extract2x(a,i) ((vec128) _mm256_extractf128_si256((vec256) (a),(i)))
#define vec256_extract(a,i) ((uint64_t) _mm256_extract_epi64((vec256) (a),(i)))

int vec256_testz(vec256 a);

#define vec256_and(a, b) _mm256_and_si256((a), (b))
#define vec256_xor(a, b) _mm256_xor_si256((a), (b))
#define vec256_or(a, b) _mm256_or_si256((a), (b))

#define vec256_sll_4x(a, s) ((vec256) _mm256_slli_epi64((vec256) (a), (s)))
#define vec256_srl_4x(a, s) ((vec256) _mm256_srli_epi64((vec256) (a), (s)))

#define vec256_unpack_low(a, b) _mm256_permute2x128_si256((a), (b), 0x20)
#define vec256_unpack_high(a, b) _mm256_permute2x128_si256((a), (b), 0x31)
#define vec256_unpack_low_2x(a, b) _mm256_unpacklo_epi64((a), (b))
#define vec256_unpack_high_2x(a, b) _mm256_unpackhi_epi64((a), (b))

vec256 vec256_or_reduce(vec256 * a);
void vec256_copy(vec256 *dest, vec256 *src);

extern void vec256_mul_asm(vec256 *, vec256 *, const vec256 *);

/* bitsliced field multiplications */
#define vec256_mul(h, f, g) vec256_mul_asm((h), (f), (g))

void vec256_sq(vec256 *, vec256 *);
void vec256_inv(vec256 *, vec256 *);

extern void vec256_maa_asm(vec256 *, vec256 *, const vec256 *);
extern void vec256_ama_asm(vec256 *, vec256 *, const vec256 *);

#endif

