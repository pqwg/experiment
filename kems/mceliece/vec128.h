/*
  This file is for functions related to 128-bit vectors
  including functions for bitsliced field operations
*/

#ifndef VEC128_H
#define VEC128_H

#include "params.h"

#include <linux/types.h>

#define _MM_MALLOC_H_INCLUDED

#include <immintrin.h>

#undef _MM_MALLOC_H_INCLUDED

typedef __m128i vec128;

#define vec128_set1_16b(a) _mm_set1_epi16((a))
#define vec128_setzero() _mm_setzero_si128();

#define vec128_extract(a, i) ((uint64_t) _mm_extract_epi64((vec128) (a), (i)))

#define vec128_and(a, b) _mm_and_si128((a), (b))
#define vec128_xor(a, b) _mm_xor_si128((a), (b))
#define vec128_or(a, b) _mm_or_si128((a), (b))

#define vec128_sll_2x(a, s) ((vec128) _mm_slli_epi64((vec128) (a), (s)))
#define vec128_srl_2x(a, s) ((vec128) _mm_srli_epi64((vec128) (a), (s)))

#define vec128_set2x(a0, a1) _mm_set_epi64x((a1), (a0))
#define vec128_unpack_low(a, b) _mm_unpacklo_epi64((a), (b))
#define vec128_unpack_high(a, b) _mm_unpackhi_epi64((a), (b))
#define vec128_setbits(a) _mm_set1_epi64x(-(a))

void vec128_copy(vec128 *dest, vec128 *src);
void vec128_add(vec128 *c, vec128 *a, vec128 *b);
vec128 vec128_or_reduce(vec128 * a);
extern void vec128_mul_asm(vec128 *, vec128 *, const vec128 *, int);

/* bitsliced field multiplications */
void vec128_mul(vec128 *h, vec128 *f, const vec128 *g);

#endif

