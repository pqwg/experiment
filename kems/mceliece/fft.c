/*
  This file is for the Gao-Mateer FFT
  sse http://www.math.clemson.edu/~sgao/papers/GM10.pdf
*/

#include "fft.h"

#include "transpose.h"
#include "vec256.h"

#include <linux/types.h>

/* input: in, polynomial in bitsliced form */
/* output: in, result of applying the radix conversions on in */
static void radix_conversions(vec128 * in, const struct mc_buffer* const buf)
{
	int i, j, k;
	vec128 t;
	uint64_t v0, v1;

	//

	for (j = 0; j <= 5; j++)
	{
		for (i = 0; i < GFBITS; i++)
		{
			v1 = vec128_extract(in[i], 1); 
			v1 ^= v1 >> 32;
			v0 = vec128_extract(in[i], 0); 
			v0 ^= v1 << 32;
			in[i] = vec128_set2x(v0, v1);
		}

		for (i = 0; i < GFBITS; i++)
		for (k = 4; k >= j; k--)
		{
			t = vec128_and(in[i], buf->mask[k][0]);
			t = vec128_srl_2x(t, 1 << k);
			in[i] = vec128_xor(in[i], t);

			t = vec128_and(in[i], buf->mask[k][1]);
			t = vec128_srl_2x(t, 1 << k);
			in[i] = vec128_xor(in[i], t);
		}

		if (j < 5)
			vec128_mul(in, in, buf->s[j]); // scaling
	}
}

static const unsigned char reversal[64] = { 
  0, 32, 16, 48,  8, 40, 24, 56, 
  4, 36, 20, 52, 12, 44, 28, 60, 
  2, 34, 18, 50, 10, 42, 26, 58, 
  6, 38, 22, 54, 14, 46, 30, 62, 
  1, 33, 17, 49,  9, 41, 25, 57, 
  5, 37, 21, 53, 13, 45, 29, 61, 
  3, 35, 19, 51, 11, 43, 27, 59, 
  7, 39, 23, 55, 15, 47, 31, 63
};

static const uint16_t beta[8] = {2522, 7827, 7801, 8035, 6897, 8167, 3476, 0};

/* input: in, result of applying the radix conversions to the input polynomial */
/* output: out, evaluation results (by applying the FFT butterflies) */
static void butterflies(vec256 out[][ GFBITS ], vec128 *in,
                        struct mc_buffer* const buf)
{
	int i, j, k, s, b;

	vec128 tmp[ GFBITS ];
	vec256 tmp0[ GFBITS ];
	vec256 tmp1[ GFBITS ];
	vec128 t[ GFBITS ];

	uint64_t v0, v1;
        
	uint64_t consts_ptr = 2;

	// boradcast

	for (j = 0; j < GFBITS; j++)
		t[j] = vec128_unpack_high(in[j], in[j]);

	for (i = 0; i < 8; i+=2)
	{
		for (j = 0; j < GFBITS; j++)
		{
			v0 = (beta[i+0] >> j) & 1; v0 = -v0;
			v1 = (beta[i+1] >> j) & 1; v1 = -v1;

			tmp[j] = vec128_set2x(v0, v1);
		}

		vec128_mul(tmp, t, tmp);

		for (j = 0; j < GFBITS; j++)
		{
			buf->pre.v[i+0][j] = vec128_unpack_low(tmp[j], tmp[j]);
			buf->pre.v[i+1][j] = vec128_unpack_high(tmp[j], tmp[j]);
		}
	}

	for (i = 0; i < GFBITS; i+=2)
	{
		if (i != GFBITS-1)
		buf->buf.v[0][1] = vec128_unpack_low(in[i+1], in[i+1] ^
                                buf->pre.v[6][i+1]);
		buf->buf.v[0][0] = vec128_unpack_low(in[i+0], in[i+0] ^
                                buf->pre.v[6][i+0]);

#define xor vec256_xor

		buf->buf.V[1] = xor(buf->buf.V[0], buf->pre.V[0][i/2]);    buf->buf.V[16] = xor(buf->buf.V[0], buf->pre.V[4][i/2]);
		buf->buf.V[3] = xor(buf->buf.V[1], buf->pre.V[1][i/2]);    buf->buf.V[48] = xor(buf->buf.V[16], buf->pre.V[5][i/2]);
                                           	buf->buf.V[49] = xor(buf->buf.V[48], buf->pre.V[0][i/2]);
		buf->buf.V[2] = xor(buf->buf.V[0], buf->pre.V[1][i/2]);    buf->buf.V[51] = xor(buf->buf.V[49], buf->pre.V[1][i/2]);
		buf->buf.V[6] = xor(buf->buf.V[2], buf->pre.V[2][i/2]);    buf->buf.V[50] = xor(buf->buf.V[51], buf->pre.V[0][i/2]);
		buf->buf.V[7] = xor(buf->buf.V[6], buf->pre.V[0][i/2]);    buf->buf.V[54] = xor(buf->buf.V[50], buf->pre.V[2][i/2]);
		buf->buf.V[5] = xor(buf->buf.V[7], buf->pre.V[1][i/2]);    buf->buf.V[55] = xor(buf->buf.V[54], buf->pre.V[0][i/2]);
                                            buf->buf.V[53] = xor(buf->buf.V[55], buf->pre.V[1][i/2]);
		buf->buf.V[4] = xor(buf->buf.V[0], buf->pre.V[2][i/2]);    buf->buf.V[52] = xor(buf->buf.V[53], buf->pre.V[0][i/2]);
		buf->buf.V[12] = xor(buf->buf.V[4], buf->pre.V[3][i/2]);   buf->buf.V[60] = xor(buf->buf.V[52], buf->pre.V[3][i/2]);
		buf->buf.V[13] = xor(buf->buf.V[12], buf->pre.V[0][i/2]);  buf->buf.V[61] = xor(buf->buf.V[60], buf->pre.V[0][i/2]);
		buf->buf.V[15] = xor(buf->buf.V[13], buf->pre.V[1][i/2]);  buf->buf.V[63] = xor(buf->buf.V[61], buf->pre.V[1][i/2]);
		buf->buf.V[14] = xor(buf->buf.V[15], buf->pre.V[0][i/2]);  buf->buf.V[62] = xor(buf->buf.V[63], buf->pre.V[0][i/2]);
		buf->buf.V[10] = xor(buf->buf.V[14], buf->pre.V[2][i/2]);  buf->buf.V[58] = xor(buf->buf.V[62], buf->pre.V[2][i/2]);
		buf->buf.V[11] = xor(buf->buf.V[10], buf->pre.V[0][i/2]);  buf->buf.V[59] = xor(buf->buf.V[58], buf->pre.V[0][i/2]);
		buf->buf.V[9] = xor(buf->buf.V[11], buf->pre.V[1][i/2]);   buf->buf.V[57] = xor(buf->buf.V[59], buf->pre.V[1][i/2]);
                                            buf->buf.V[56] = xor(buf->buf.V[57], buf->pre.V[0][i/2]);
		buf->buf.V[8] = xor(buf->buf.V[0], buf->pre.V[3][i/2]);    buf->buf.V[40] = xor(buf->buf.V[56], buf->pre.V[4][i/2]);
		buf->buf.V[24] = xor(buf->buf.V[8], buf->pre.V[4][i/2]);   buf->buf.V[41] = xor(buf->buf.V[40], buf->pre.V[0][i/2]);
		buf->buf.V[25] = xor(buf->buf.V[24], buf->pre.V[0][i/2]);  buf->buf.V[43] = xor(buf->buf.V[41], buf->pre.V[1][i/2]);
		buf->buf.V[27] = xor(buf->buf.V[25], buf->pre.V[1][i/2]);  buf->buf.V[42] = xor(buf->buf.V[43], buf->pre.V[0][i/2]);
		buf->buf.V[26] = xor(buf->buf.V[27], buf->pre.V[0][i/2]);  buf->buf.V[46] = xor(buf->buf.V[42], buf->pre.V[2][i/2]);
		buf->buf.V[30] = xor(buf->buf.V[26], buf->pre.V[2][i/2]);  buf->buf.V[47] = xor(buf->buf.V[46], buf->pre.V[0][i/2]);
		buf->buf.V[31] = xor(buf->buf.V[30], buf->pre.V[0][i/2]);  buf->buf.V[45] = xor(buf->buf.V[47], buf->pre.V[1][i/2]);
		buf->buf.V[29] = xor(buf->buf.V[31], buf->pre.V[1][i/2]);  buf->buf.V[44] = xor(buf->buf.V[45], buf->pre.V[0][i/2]);
		buf->buf.V[28] = xor(buf->buf.V[29], buf->pre.V[0][i/2]);  buf->buf.V[36] = xor(buf->buf.V[44], buf->pre.V[3][i/2]);
		buf->buf.V[20] = xor(buf->buf.V[28], buf->pre.V[3][i/2]);  buf->buf.V[37] = xor(buf->buf.V[36], buf->pre.V[0][i/2]);
		buf->buf.V[21] = xor(buf->buf.V[20], buf->pre.V[0][i/2]);  buf->buf.V[39] = xor(buf->buf.V[37], buf->pre.V[1][i/2]);
		buf->buf.V[23] = xor(buf->buf.V[21], buf->pre.V[1][i/2]);  buf->buf.V[38] = xor(buf->buf.V[39], buf->pre.V[0][i/2]);
		buf->buf.V[22] = xor(buf->buf.V[23], buf->pre.V[0][i/2]);  buf->buf.V[34] = xor(buf->buf.V[38], buf->pre.V[2][i/2]);
		buf->buf.V[18] = xor(buf->buf.V[22], buf->pre.V[2][i/2]);  buf->buf.V[35] = xor(buf->buf.V[34], buf->pre.V[0][i/2]);
		buf->buf.V[19] = xor(buf->buf.V[18], buf->pre.V[0][i/2]);  buf->buf.V[33] = xor(buf->buf.V[35], buf->pre.V[1][i/2]);
		buf->buf.V[17] = xor(buf->buf.V[19], buf->pre.V[1][i/2]);  buf->buf.V[32] = xor(buf->buf.V[33], buf->pre.V[0][i/2]);

#undef xor

		// transpose

		transpose_64x256_sp(buf->buf.V);
	
		for (j = 0; j < 32; j++)
		{
			if (i != GFBITS-1)
			out[j][i+1] = vec256_unpack_high(buf->buf.V[ reversal[2*j+0] ], buf->buf.V[ reversal[2*j+1] ]);
			out[j][i+0] = vec256_unpack_low (buf->buf.V[ reversal[2*j+0] ], buf->buf.V[ reversal[2*j+1] ]);
		}
	}

	// butterflies

	for (k = 0; k < 32; k+=2)
	{
		for (b = 0; b < GFBITS; b++) tmp0[b] = vec256_unpack_low (out[k][b], out[k+1][b]);
		for (b = 0; b < GFBITS; b++) tmp1[b] = vec256_unpack_high (out[k][b], out[k+1][b]); 

		vec256_maa_asm(tmp0, tmp1, buf->consts[1]);

		for (b = 0; b < GFBITS; b++) out[k][b] = vec256_unpack_low (tmp0[b], tmp1[b]);
		for (b = 0; b < GFBITS; b++) out[k+1][b] = vec256_unpack_high (tmp0[b], tmp1[b]);
	}

	for (i = 0; i <= 4; i++)
	{
		s = 1 << i;

		for (j = 0; j < 32; j += 2*s)
		for (k = j; k < j+s; k++)
		{
			vec256_maa_asm(out[k], out[k+s], buf->consts[ consts_ptr + (k-j) ]);
		}

		consts_ptr += (1 << i);
	}
}

/* input: in, polynomial in bitsliced form */
/* output: out, bitsliced results of evaluating in all the field elements */
void fft(vec256 out[][GFBITS], vec128 *in, struct mc_buffer* const buf)
{
	radix_conversions(in, buf);
	butterflies(out, in, buf);
}

