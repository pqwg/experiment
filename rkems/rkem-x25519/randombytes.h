#ifndef PQWG_RANDOMBYTES_H
#define PQWG_RANDOMBYTES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
#define randombytes PQWG_randombytes
int randombytes(uint8_t *output, size_t n);

#endif /* PQWG_RANDOMBYTES_H */
