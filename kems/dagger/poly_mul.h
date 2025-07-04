#ifndef __SABER_POLY_MUL
#define __SABER_POLY_MUL

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include "SABER_params.h"

void pol_mul(uint16_t* a, uint16_t* b, uint16_t* res, uint16_t p, uint32_t n,
             uint16_t c[512], uint16_t* const tc_buf);

void pol_mul_sb(int16_t* a, int16_t* b, int16_t* res, uint16_t p, uint32_t n,uint32_t start);

void toom_cook_4way(const uint16_t* a1, const uint16_t* b1, uint16_t* result,
                    uint16_t * const tc_buf);

//static int16_t reduce(int16_t a, int64_t p);

#endif
