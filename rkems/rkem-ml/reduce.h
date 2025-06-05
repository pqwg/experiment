#ifndef PQCLEAN_MLKEM512_CLEAN_REDUCE_H
#define PQCLEAN_MLKEM512_CLEAN_REDUCE_H
#include "params.h"

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

// For Q = 3329
// #define MONT (-1044) // 2^16 mod q
// #define MONTINV 169  // 2^-16 mod q
// #define QINV (-3327) // q^-1 mod 2^16

// For Q = 10753
#define MONT 1018    // 2^16 mod q
#define MONTINV 1764 // 2^-16 mod q
#define QINV (-10751) // q^-1 mod 2^16

int16_t PQCLEAN_MLKEM512_CLEAN_montgomery_reduce(int32_t a);

int16_t PQCLEAN_MLKEM512_CLEAN_barrett_reduce(int16_t a);

#endif
