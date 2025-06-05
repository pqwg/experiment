/*
  This file is for transpose of the Gao-Mateer FFT
  Functions with names ending with _tr are (roughly) the transpose of the corresponding functions in fft.c
*/

#include "fft_tr.h"

#include "transpose.h"

#include <linux/types.h>

static void radix_conversions_tr(vec256 *in, const struct mc_buffer* const buf)
{
	int i, j, k;
	vec256 t;
	uint64_t v[4];
        
	//

	for (j = 6; j >= 0; j--)
	{
		if (j < 6)
		{
			vec256_mul(in, in, buf->rct_s[j]); // scaling
		}

		for (k = j; k <= 4; k++)
		for (i = 0; i < GFBITS; i++)
		{
			t = vec256_and(in[i], buf->rct_mask[k][0]);
			t = vec256_sll_4x(t, 1 << k);
			in[i] = vec256_xor(in[i], t);

			t = vec256_and(in[i], buf->rct_mask[k][1]);
			t = vec256_sll_4x(t, 1 << k);
			in[i] = vec256_xor(in[i], t);
		}

		if (j <= 5)
		for (i = 0; i < GFBITS; i++)
		{
			v[0] = vec256_extract(in[i], 0);		
			v[1] = vec256_extract(in[i], 1);		
			v[2] = vec256_extract(in[i], 2);		
			v[3] = vec256_extract(in[i], 3);		

			v[1] ^= v[0] >> 32;
			v[1] ^= v[1] << 32;
			v[3] ^= v[2] >> 32;
			v[3] ^= v[3] << 32;

			in[i] = vec256_set4x(v[0], v[1], v[2], v[3]);
		}

		for (i = 0; i < GFBITS; i++)
		{
			v[0] = vec256_extract(in[i], 0);		
			v[1] = vec256_extract(in[i], 1);		
			v[2] = vec256_extract(in[i], 2);		
			v[3] = vec256_extract(in[i], 3);		
	
			v[2] ^= v[1];
			v[3] ^= v[2];

			in[i] = vec256_set4x(v[0], v[1], v[2], v[3]);
		}

	}
}

// data for butterflies_tr
static const unsigned char reversal[] = {
    0, 32, 16, 48,  8, 40, 24, 56, 
    4, 36, 20, 52, 12, 44, 28, 60, 
    2, 34, 18, 50, 10, 42, 26, 58, 
    6, 38, 22, 54, 14, 46, 30, 62, 
    1, 33, 17, 49,  9, 41, 25, 57, 
    5, 37, 21, 53, 13, 45, 29, 61, 
    3, 35, 19, 51, 11, 43, 27, 59, 
    7, 39, 23, 55, 15, 47, 31, 63
};

static const uint16_t beta[6] = {5246, 5306, 6039, 6685, 4905, 6755};

static void butterflies_tr(vec256 *out, vec256 in[][ GFBITS ],
                            struct mc_buffer* const mcbuf)
{
	int i, j, k, s, b;

	vec256 t0[ GFBITS ];
	vec256 t1[ GFBITS ];
	vec256 t;

	vec128 out128[ GFBITS ][ 2 ];
	vec128 tmp[ GFBITS ];

	uint64_t v[4];
	uint64_t consts_ptr = 33;

	// butterflies

	for (i = 4; i >= 0; i--)
	{
		s = 1 << i;
		consts_ptr -= s;

		for (j = 0; j < 32; j += 2*s)
		for (k = j; k < j+s; k++)
		{
			vec256_ama_asm(in[k], in[k+s], mcbuf->consts[ consts_ptr + (k-j) ]);
		}

	}

	for (k = 0; k < 32; k+=2)
	{
		for (b = 0; b < GFBITS; b++) t0[b] = vec256_unpack_low(in[k][b], in[k+1][b]);
		for (b = 0; b < GFBITS; b++) t1[b] = vec256_unpack_high(in[k][b], in[k+1][b]);

		vec256_ama_asm(t0, t1, mcbuf->consts[1]);

		for (b = 0; b < GFBITS; b++) in[k][b] = vec256_unpack_low(t0[b], t1[b]);
		for (b = 0; b < GFBITS; b++) in[k+1][b] = vec256_unpack_high(t0[b], t1[b]);

		for (b = 0; b < GFBITS; b++) t0[b] = vec256_unpack_low_2x(in[k][b], in[k+1][b]);
		for (b = 0; b < GFBITS; b++) t1[b] = vec256_unpack_high_2x(in[k][b], in[k+1][b]);

		vec256_ama_asm(t0, t1, mcbuf->consts[0]);

		for (b = 0; b < GFBITS; b++) in[k+0][b] = vec256_unpack_low_2x(t0[b], t1[b]);
		for (b = 0; b < GFBITS; b++) in[k+1][b] = vec256_unpack_high_2x(t0[b], t1[b]);
	}


	// boradcast

	for (i = 0; i < GFBITS; i+=2)
	{
		// transpose

		for (k = 0; k < 32; k++)
		{
			if (i != GFBITS-1) {
			mcbuf->buf.v[ reversal[2*k+0] ][1] = vec256_extract2x(in[ k ][i+1], 0);
			mcbuf->buf.v[ reversal[2*k+1] ][1] = vec256_extract2x(in[ k ][i+1], 1); 
			}

			mcbuf->buf.v[ reversal[2*k+0] ][0] = vec256_extract2x(in[ k ][i+0], 0);
			mcbuf->buf.v[ reversal[2*k+1] ][0] = vec256_extract2x(in[ k ][i+0], 1);
		}

		transpose_64x256_sp(mcbuf->buf.V);

		//

#define xor vec256_xor

		mcbuf->pre_tr.V[0][i/2] = mcbuf->buf.V[32]; mcbuf->buf.V[33] = xor(mcbuf->buf.V[33], mcbuf->buf.V[32]);
		mcbuf->pre_tr.V[1][i/2] = mcbuf->buf.V[33]; mcbuf->buf.V[35] = xor(mcbuf->buf.V[35], mcbuf->buf.V[33]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[35]); mcbuf->buf.V[34] = xor(mcbuf->buf.V[34], mcbuf->buf.V[35]);
		mcbuf->pre_tr.V[2][i/2] = mcbuf->buf.V[34]; mcbuf->buf.V[38] = xor(mcbuf->buf.V[38], mcbuf->buf.V[34]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[38]); mcbuf->buf.V[39] = xor(mcbuf->buf.V[39], mcbuf->buf.V[38]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[39]); mcbuf->buf.V[37] = xor(mcbuf->buf.V[37], mcbuf->buf.V[39]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[37]); mcbuf->buf.V[36] = xor(mcbuf->buf.V[36], mcbuf->buf.V[37]);
		mcbuf->pre_tr.V[3][i/2] = mcbuf->buf.V[36]; mcbuf->buf.V[44] = xor(mcbuf->buf.V[44], mcbuf->buf.V[36]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[44]); mcbuf->buf.V[45] = xor(mcbuf->buf.V[45], mcbuf->buf.V[44]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[45]); mcbuf->buf.V[47] = xor(mcbuf->buf.V[47], mcbuf->buf.V[45]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[47]); mcbuf->buf.V[46] = xor(mcbuf->buf.V[46], mcbuf->buf.V[47]);
		mcbuf->pre_tr.V[2][i/2] = xor(mcbuf->pre_tr.V[2][i/2], mcbuf->buf.V[46]); mcbuf->buf.V[42] = xor(mcbuf->buf.V[42], mcbuf->buf.V[46]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[42]); mcbuf->buf.V[43] = xor(mcbuf->buf.V[43], mcbuf->buf.V[42]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[43]); mcbuf->buf.V[41] = xor(mcbuf->buf.V[41], mcbuf->buf.V[43]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[41]); mcbuf->buf.V[40] = xor(mcbuf->buf.V[40], mcbuf->buf.V[41]);
		mcbuf->pre_tr.V[4][i/2] = mcbuf->buf.V[40]; mcbuf->buf.V[56] = xor(mcbuf->buf.V[56], mcbuf->buf.V[40]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[56]); mcbuf->buf.V[57] = xor(mcbuf->buf.V[57], mcbuf->buf.V[56]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[57]); mcbuf->buf.V[59] = xor(mcbuf->buf.V[59], mcbuf->buf.V[57]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[59]); mcbuf->buf.V[58] = xor(mcbuf->buf.V[58], mcbuf->buf.V[59]);
		mcbuf->pre_tr.V[2][i/2] = xor(mcbuf->pre_tr.V[2][i/2], mcbuf->buf.V[58]); mcbuf->buf.V[62] = xor(mcbuf->buf.V[62], mcbuf->buf.V[58]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[62]); mcbuf->buf.V[63] = xor(mcbuf->buf.V[63], mcbuf->buf.V[62]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[63]); mcbuf->buf.V[61] = xor(mcbuf->buf.V[61], mcbuf->buf.V[63]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[61]); mcbuf->buf.V[60] = xor(mcbuf->buf.V[60], mcbuf->buf.V[61]);
		mcbuf->pre_tr.V[3][i/2] = xor(mcbuf->pre_tr.V[3][i/2], mcbuf->buf.V[60]); mcbuf->buf.V[52] = xor(mcbuf->buf.V[52], mcbuf->buf.V[60]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[52]); mcbuf->buf.V[53] = xor(mcbuf->buf.V[53], mcbuf->buf.V[52]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[53]); mcbuf->buf.V[55] = xor(mcbuf->buf.V[55], mcbuf->buf.V[53]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[55]); mcbuf->buf.V[54] = xor(mcbuf->buf.V[54], mcbuf->buf.V[55]);
		mcbuf->pre_tr.V[2][i/2] = xor(mcbuf->pre_tr.V[2][i/2], mcbuf->buf.V[54]); mcbuf->buf.V[50] = xor(mcbuf->buf.V[50], mcbuf->buf.V[54]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[50]); mcbuf->buf.V[51] = xor(mcbuf->buf.V[51], mcbuf->buf.V[50]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[51]); mcbuf->buf.V[49] = xor(mcbuf->buf.V[49], mcbuf->buf.V[51]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[49]); mcbuf->buf.V[48] = xor(mcbuf->buf.V[48], mcbuf->buf.V[49]);
		mcbuf->pre_tr.V[5][i/2] = mcbuf->buf.V[48]; mcbuf->buf.V[16] = xor(mcbuf->buf.V[16], mcbuf->buf.V[48]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[16]); mcbuf->buf.V[17] = xor(mcbuf->buf.V[17], mcbuf->buf.V[16]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[17]); mcbuf->buf.V[19] = xor(mcbuf->buf.V[19], mcbuf->buf.V[17]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[19]); mcbuf->buf.V[18] = xor(mcbuf->buf.V[18], mcbuf->buf.V[19]);
		mcbuf->pre_tr.V[2][i/2] = xor(mcbuf->pre_tr.V[2][i/2], mcbuf->buf.V[18]); mcbuf->buf.V[22] = xor(mcbuf->buf.V[22], mcbuf->buf.V[18]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[22]); mcbuf->buf.V[23] = xor(mcbuf->buf.V[23], mcbuf->buf.V[22]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[23]); mcbuf->buf.V[21] = xor(mcbuf->buf.V[21], mcbuf->buf.V[23]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[21]); mcbuf->buf.V[20] = xor(mcbuf->buf.V[20], mcbuf->buf.V[21]);
		mcbuf->pre_tr.V[3][i/2] = xor(mcbuf->pre_tr.V[3][i/2], mcbuf->buf.V[20]); mcbuf->buf.V[28] = xor(mcbuf->buf.V[28], mcbuf->buf.V[20]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[28]); mcbuf->buf.V[29] = xor(mcbuf->buf.V[29], mcbuf->buf.V[28]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[29]); mcbuf->buf.V[31] = xor(mcbuf->buf.V[31], mcbuf->buf.V[29]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[31]); mcbuf->buf.V[30] = xor(mcbuf->buf.V[30], mcbuf->buf.V[31]);
		mcbuf->pre_tr.V[2][i/2] = xor(mcbuf->pre_tr.V[2][i/2], mcbuf->buf.V[30]); mcbuf->buf.V[26] = xor(mcbuf->buf.V[26], mcbuf->buf.V[30]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[26]); mcbuf->buf.V[27] = xor(mcbuf->buf.V[27], mcbuf->buf.V[26]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[27]); mcbuf->buf.V[25] = xor(mcbuf->buf.V[25], mcbuf->buf.V[27]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[25]); mcbuf->buf.V[24] = xor(mcbuf->buf.V[24], mcbuf->buf.V[25]);
		mcbuf->pre_tr.V[4][i/2] = xor(mcbuf->pre_tr.V[4][i/2], mcbuf->buf.V[24]); mcbuf->buf.V[8] = xor(mcbuf->buf.V[8], mcbuf->buf.V[24]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[8]); mcbuf->buf.V[9] = xor(mcbuf->buf.V[9], mcbuf->buf.V[8]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[9]); mcbuf->buf.V[11] = xor(mcbuf->buf.V[11], mcbuf->buf.V[9]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[11]); mcbuf->buf.V[10] = xor(mcbuf->buf.V[10], mcbuf->buf.V[11]);
		mcbuf->pre_tr.V[2][i/2] = xor(mcbuf->pre_tr.V[2][i/2], mcbuf->buf.V[10]); mcbuf->buf.V[14] = xor(mcbuf->buf.V[14], mcbuf->buf.V[10]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[14]); mcbuf->buf.V[15] = xor(mcbuf->buf.V[15], mcbuf->buf.V[14]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[15]); mcbuf->buf.V[13] = xor(mcbuf->buf.V[13], mcbuf->buf.V[15]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[13]); mcbuf->buf.V[12] = xor(mcbuf->buf.V[12], mcbuf->buf.V[13]);
		mcbuf->pre_tr.V[3][i/2] = xor(mcbuf->pre_tr.V[3][i/2], mcbuf->buf.V[12]); mcbuf->buf.V[4] = xor(mcbuf->buf.V[4], mcbuf->buf.V[12]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[4]); mcbuf->buf.V[5] = xor(mcbuf->buf.V[5], mcbuf->buf.V[4]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[5]); mcbuf->buf.V[7] = xor(mcbuf->buf.V[7], mcbuf->buf.V[5]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[7]); mcbuf->buf.V[6] = xor(mcbuf->buf.V[6], mcbuf->buf.V[7]);
		mcbuf->pre_tr.V[2][i/2] = xor(mcbuf->pre_tr.V[2][i/2], mcbuf->buf.V[6]); mcbuf->buf.V[2] = xor(mcbuf->buf.V[2], mcbuf->buf.V[6]);
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[2]); mcbuf->buf.V[3] = xor(mcbuf->buf.V[3], mcbuf->buf.V[2]);
		mcbuf->pre_tr.V[1][i/2] = xor(mcbuf->pre_tr.V[1][i/2], mcbuf->buf.V[3]); mcbuf->buf.V[1] = xor(mcbuf->buf.V[1], mcbuf->buf.V[3]);
	
		mcbuf->pre_tr.V[0][i/2] = xor(mcbuf->pre_tr.V[0][i/2], mcbuf->buf.V[1]); t = xor(mcbuf->buf.V[0], mcbuf->buf.V[1]);

		if (i != GFBITS-1)
		out128[i+1][0] = vec256_extract2x(t, 1);
		out128[i+0][0] = vec256_extract2x(t, 0);
#undef xor

	}	

	//

	for (j = 0; j < GFBITS; j++) tmp[j] = vec128_setbits((beta[0] >> j) & 1);

	vec128_mul(tmp, mcbuf->pre_tr.v[0], tmp);

	for (b = 0; b < GFBITS; b++) out128[b][1] = tmp[b];

	for (i = 1; i < 6; i++)
	{
		for (j = 0; j < GFBITS; j++) tmp[j] = vec128_setbits((beta[i] >> j) & 1);

		vec128_mul(tmp, mcbuf->pre_tr.v[i], tmp);

		for (b = 0; b < GFBITS; b++) out128[b][1] = vec128_xor(out128[b][1], tmp[b]);
	}

	for (b = 0; b < GFBITS; b++)
	{
		v[0] = vec128_extract(out128[b][0], 0);
		v[1] = vec128_extract(out128[b][0], 1);
		v[2] = vec128_extract(out128[b][1], 0);
		v[3] = vec128_extract(out128[b][1], 1);
		
		out[b] = vec256_set4x(v[0], v[1], v[2], v[3]);
	}
}

/* justifying the length of the output */
static void postprocess(vec256 *out)
{
	int i;
	uint64_t v[4];

	for (i = 0; i < 13; i++)
	{
		v[0] = vec256_extract(out[i], 0);
		v[1] = vec256_extract(out[i], 1);
		v[2] = vec256_extract(out[i], 2);
		v[3] = vec256_extract(out[i], 3);

		v[3] = 0;

		out[i] = vec256_set4x(v[0], v[1], v[2], v[3]);
	}
}

void fft_tr(vec256 *out, vec256 in[][ GFBITS ], struct mc_buffer* const buf)
{
	butterflies_tr(out, in, buf);
	radix_conversions_tr(out, buf);

	postprocess(out);
}

