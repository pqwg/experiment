#ifndef __MC_KERN_MC_BUF_H
#define __MC_KERN_MC_BUF_H

#include "params.h"
#include "vec128.h"
#include "vec256.h"

#include <linux/string.h>

// huge buffers for McEliece decryption
struct mc_buffer {
    // decrypt
    vec256 inv[32][GFBITS ];
    vec256 scaled[32][GFBITS ];
    vec256 eval[32][GFBITS ];

    union {
        vec128 error128[64];
        vec128 recv128[64];
    } vec128_64;

    union {
        vec256 error256[32];
        vec256 recv256[32];
    } vec256_32;

    vec256 s_priv[ GFBITS ];
    vec256 s_priv_cmp[ GFBITS ];
    vec128 locator[ GFBITS ];

    vec128 bits_int[25][32];

    // radix_conversions
    vec128 mask[5][2];
    vec128 s[5][GFBITS];

    // butterfly
    union {
            vec128 v[8][  GFBITS+1    ];
            vec256 V[8][ (GFBITS+1)/2 ];
    } pre;

    union {
            vec128 v[64][ 2 ];
            vec256 V[64];
    } buf;

    union {
            vec128 v[6][  GFBITS+1    ];
            vec256 V[6][ (GFBITS+1)/2 ];
    } pre_tr;

    vec256 consts[ 33 ][ GFBITS ];

    // radix_conversions_tr
    vec256 rct_mask[6][2];
    vec256 rct_s[6][GFBITS];
};

void init_mcbuf(struct mc_buffer* const buf);
void clear_mcbuf(struct mc_buffer* const buf);

#endif
