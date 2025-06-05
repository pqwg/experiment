#ifndef PQCLEAN_MLKEM512_CLEAN_NTT_H
#define PQCLEAN_MLKEM512_CLEAN_NTT_H
#include "params.h"

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

extern const int16_t PQCLEAN_MLKEM512_CLEAN_zetas[128];

void PQCLEAN_MLKEM512_CLEAN_ntt(int16_t r[256]);

void PQCLEAN_MLKEM512_CLEAN_invntt(int16_t r[256]);

void PQCLEAN_MLKEM512_CLEAN_basemul(int16_t r[256], const int16_t a[256], const int16_t b[256]);

#endif
