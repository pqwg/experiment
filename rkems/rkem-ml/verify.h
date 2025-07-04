#ifndef PQCLEAN_MLKEM512_CLEAN_VERIFY_H
#define PQCLEAN_MLKEM512_CLEAN_VERIFY_H
#include "params.h"
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

int PQCLEAN_MLKEM512_CLEAN_verify(const uint8_t *a, const uint8_t *b, size_t len);

void PQCLEAN_MLKEM512_CLEAN_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

void PQCLEAN_MLKEM512_CLEAN_cmov_int16(int16_t *r, int16_t v, uint16_t b);

#endif
