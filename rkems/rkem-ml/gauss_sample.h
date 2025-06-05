//  gauss_sample.h
//  Copyright (c) 2025 Reinforced KEM Team. See LICENSE.

#ifndef _GAUSS_SAMPLE_H_
#define _GAUSS_SAMPLE_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#include "params.h"

void sample_sk_poly(poly *r, const uint8_t seed[KYBER_SYMBYTES], const uint8_t nonce);
void sample_r_poly(poly *r, const uint8_t seed[KYBER_SYMBYTES], const uint8_t nonce);
void sample_noise_poly(poly *r, const uint8_t seed[KYBER_SYMBYTES], const uint8_t nonce);

//  _XOF_SAMPLE_H_
#endif
