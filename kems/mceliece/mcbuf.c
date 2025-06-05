#include "mcbuf.h"

static void init_rct_mask(vec256 mask[6][2]) {
    mask[0][0] = vec256_set4x(0x2222222222222222, 0x2222222222222222, 0x2222222222222222, 0x2222222222222222);
    mask[0][1] = vec256_set4x(0x4444444444444444, 0x4444444444444444, 0x4444444444444444, 0x4444444444444444);
    mask[1][0] = vec256_set4x(0x0C0C0C0C0C0C0C0C, 0x0C0C0C0C0C0C0C0C, 0x0C0C0C0C0C0C0C0C, 0x0C0C0C0C0C0C0C0C);
    mask[1][1] = vec256_set4x(0x3030303030303030, 0x3030303030303030, 0x3030303030303030, 0x3030303030303030);
    mask[2][0] = vec256_set4x(0x00F000F000F000F0, 0x00F000F000F000F0, 0x00F000F000F000F0, 0x00F000F000F000F0);
    mask[2][1] = vec256_set4x(0x0F000F000F000F00, 0x0F000F000F000F00, 0x0F000F000F000F00, 0x0F000F000F000F00);
    mask[3][0] = vec256_set4x(0x0000FF000000FF00, 0x0000FF000000FF00, 0x0000FF000000FF00, 0x0000FF000000FF00);
    mask[3][1] = vec256_set4x(0x00FF000000FF0000, 0x00FF000000FF0000, 0x00FF000000FF0000, 0x00FF000000FF0000);
    mask[4][0] = vec256_set4x(0x00000000FFFF0000, 0x00000000FFFF0000, 0x00000000FFFF0000, 0x00000000FFFF0000);
    mask[4][1] = vec256_set4x(0x0000FFFF00000000, 0x0000FFFF00000000, 0x0000FFFF00000000, 0x0000FFFF00000000);
    mask[5][0] = vec256_set4x(0xFFFFFFFF00000000, 0xFFFFFFFF00000000, 0xFFFFFFFF00000000, 0xFFFFFFFF00000000);
    mask[5][1] = vec256_set4x(0x00000000FFFFFFFF, 0x00000000FFFFFFFF, 0x00000000FFFFFFFF, 0x00000000FFFFFFFF);
}

static void init_rct_s(vec256 s[6][GFBITS]) {
#include "scalars_4x_init.data"
}

static void init_consts(vec256 consts[33][GFBITS]) {
#include "consts_init.data"
}

static void init_v128_mask(vec128 mask[5][2]) 
{
    mask[0][0] = vec128_set2x(0x8888888888888888, 0x8888888888888888);
    mask[0][1] = vec128_set2x(0x4444444444444444, 0x4444444444444444);
    mask[1][0] = vec128_set2x(0xC0C0C0C0C0C0C0C0, 0xC0C0C0C0C0C0C0C0);
    mask[1][1] = vec128_set2x(0x3030303030303030, 0x3030303030303030);
    mask[2][0] = vec128_set2x(0xF000F000F000F000, 0xF000F000F000F000);
    mask[2][1] = vec128_set2x(0x0F000F000F000F00, 0x0F000F000F000F00);
    mask[3][0] = vec128_set2x(0xFF000000FF000000, 0xFF000000FF000000);
    mask[3][1] = vec128_set2x(0x00FF000000FF0000, 0x00FF000000FF0000);
    mask[4][0] = vec128_set2x(0xFFFF000000000000, 0xFFFF000000000000);
    mask[4][1] = vec128_set2x(0x0000FFFF00000000, 0x0000FFFF00000000);
}

static void init_v128_s(vec128 s[5][GFBITS]) {
#include "scalars_2x_init.data"
}


void init_mcbuf(struct mc_buffer* const buf) {
    init_rct_mask(buf->rct_mask);
    init_rct_s(buf->rct_s);
    init_consts(buf->consts);
    init_v128_mask(buf->mask);
    init_v128_s(buf->s);
}

void clear_mcbuf(struct mc_buffer* const buf) {
    memset(buf->inv, 0x0, sizeof(vec256) * 32 * GFBITS);
    memset(buf->scaled, 0x0, sizeof(vec256) * 32 * GFBITS);
    memset(buf->eval, 0x0, sizeof(vec256) * 32 * GFBITS);
    memset(&buf->vec128_64, 0x0, sizeof(buf->vec128_64));
    memset(&buf->vec256_32, 0x0, sizeof(buf->vec256_32));
    memset(buf->s_priv, 0x0, sizeof(256) * GFBITS);
    memset(buf->s_priv_cmp, 0x0, sizeof(vec256) * GFBITS);
    memset(buf->locator, 0x0, sizeof(vec128) * GFBITS);
    memset(buf->bits_int, 0x0, sizeof(vec128) * 25 * 32);
    memset(&buf->pre, 0x0, sizeof(buf->pre));
    memset(&buf->buf, 0x0, sizeof(buf->buf));
    memset(&buf->pre_tr, 0x0, sizeof(buf->pre_tr));
}
