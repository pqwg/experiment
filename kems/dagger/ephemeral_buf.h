#ifndef __KERN_EPHEMERAL_BUF_H
#define __KERN_EPHEMERAL_BUF_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <string.h>
#endif

#include "poly.h"
#include "SABER_params.h"

// huge buffers for ephemeral key pair generation
struct eph_buffer {
    unsigned char genmat_buf[13 * SABER_N / 8 * SABER_K * SABER_K];
    polyvec a[SABER_K];// skpv;
    uint16_t skpv[SABER_K][SABER_N];
    uint16_t res[SABER_K][SABER_N];
    uint16_t pkcl[SABER_K][SABER_N];
    uint16_t message[SABER_KEYBYTES*8];
    uint16_t pol_mul_tmp[512];
    uint16_t tc_tmp[(SABER_N >> 2) * 14 + (SABER_N << 1) * 7];
};

#endif
