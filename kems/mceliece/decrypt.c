/*
  This file is for Niederreiter decryption
*/

#include "decrypt.h"

#include "params.h"
#include "fft_tr.h"
#include "benes.h"
#include "util.h"
#include "fft.h"
#include "bm.h"

static void scaling(vec256 out[][GFBITS], vec256 inv[][GFBITS],
                    const unsigned char *sk, vec256 *recv,
                    vec128 sk_int[GFBITS], vec256 eval[][GFBITS],
                    vec256 tmp[GFBITS], struct mc_buffer* const buf)
{
	int i, j;

	// computing inverses

	irr_load(sk_int, sk);

	fft(eval, sk_int, buf);

	for (i = 0; i < 32; i++)
		vec256_sq(eval[i], eval[i]);

	vec256_copy(inv[0], eval[0]);

	for (i = 1; i < 32; i++)
		vec256_mul(inv[i], inv[i-1], eval[i]);

	vec256_inv(tmp, inv[31]);

	for (i = 30; i >= 0; i--)
	{
		vec256_mul(inv[i+1], tmp, inv[i]);
		vec256_mul(tmp, tmp, eval[i+1]);
	}

	vec256_copy(inv[0], tmp);
	
	//

	for (i = 0; i < 32; i++)
	for (j = 0; j < GFBITS; j++)
		out[i][j] = vec256_and(inv[i][j], recv[i]);
}

static void preprocess(vec128 *recv, const unsigned char *s)
{
	int i;
	unsigned char r[ 1024 ];

	for (i = 0; i < SYND_BYTES; i++)    
		r[i] = s[i];

	for (i = SYND_BYTES; i < 1024; i++) 
		r[i] = 0;

	for (i = 0; i < 64; i++)
		recv[i] = load16(r + i*16);
}

static void postprocess(unsigned char * e, vec128 * err)
{
	int i;
	unsigned char error8[ (1 << GFBITS)/8 ];
	uint64_t v[2];

	for (i = 0; i < 64; i++)
	{
		v[0] = vec128_extract(err[i], 0);
		v[1] = vec128_extract(err[i], 1);

		store8(error8 + i*16 + 0, v[0]);
		store8(error8 + i*16 + 8, v[1]);
	}

	for (i = 0; i < SYS_N/8; i++)
		e[i] = error8[i];
}

static void scaling_inv(vec256 out[][GFBITS], vec256 inv[][GFBITS], vec256 *recv)
{
	int i, j;

	for (i = 0; i < 32; i++)
	for (j = 0; j < GFBITS; j++)
		out[i][j] = vec256_and(inv[i][j], recv[i]);
}

static int weight_check(unsigned char * e, vec128 * error)
{
	int i;
	uint16_t w0 = 0;
	uint16_t w1 = 0;
	uint16_t check;

	for (i = 0; i < 64; i++)
	{
		w0 += __builtin_popcountll( vec128_extract(error[i], 0) );
		w0 += __builtin_popcountll( vec128_extract(error[i], 1) );
	}

	for (i = 0; i < SYS_N/8; i++)
		w1 += __builtin_popcountll( e[i] );

	check = (w0 ^ SYS_T) | (w1 ^ SYS_T);
	check -= 1;
	check >>= 15;

	return check;
}

static uint64_t synd_cmp(vec256 *s0 , vec256 *s1)
{
	int i;
	vec256 diff;

	diff = vec256_xor(s0[0], s1[0]);

	for (i = 1; i < GFBITS; i++)
		diff = vec256_or(diff, vec256_xor(s0[i], s1[i]));
	
	return vec256_testz(diff);
}

static void reformat_128to256(vec256 * out, vec128 * in)
{
	int i;
	uint64_t v[4];

	for (i = 0; i < 32; i++)
	{
		v[0] = vec128_extract(in[2*i+0], 0);
		v[1] = vec128_extract(in[2*i+0], 1);
		v[2] = vec128_extract(in[2*i+1], 0);
		v[3] = vec128_extract(in[2*i+1], 1);

		out[i] = vec256_set4x(v[0], v[1], v[2], v[3]);
	}
}

static void reformat_256to128(vec128 * out, vec256 * in)
{
	int i;
	uint64_t v[4];

	for (i = 0; i < 32; i++)
	{
		v[0] = vec256_extract(in[i], 0);
		v[1] = vec256_extract(in[i], 1);
		v[2] = vec256_extract(in[i], 2);
		v[3] = vec256_extract(in[i], 3);

		out[2*i+0] = vec128_set2x(v[0], v[1]);
		out[2*i+1] = vec128_set2x(v[2], v[3]);
	}
}

/* Niederreiter decryption with the Berlekamp decoder */
/* intput: sk, secret key */
/*         s, ciphertext (syndrome) */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
int decrypt(unsigned char *e, const unsigned char *sk, const unsigned char *s,
            struct mc_buffer* const buf) {
	int i; 

	uint16_t check_synd;
	uint16_t check_weight;

	vec256 (* inv) [GFBITS] = buf->inv;
	vec256 (* scaled) [GFBITS] = buf->scaled;
	vec256 (* eval) [GFBITS] = buf->eval;

	vec128* error128 = buf->vec128_64.error128;
	vec256* error256 = buf->vec256_32.error256;

	vec256* s_priv = buf->s_priv;
	vec256* s_priv_cmp = buf->s_priv_cmp;
	vec128* locator = buf->locator;

	vec128* recv128 = buf->vec128_64.recv128;
	vec256* recv256 = buf->vec256_32.recv256;
	vec256 allone;

	vec128 (* bits_int ) [32] = buf->bits_int;

	// Berlekamp decoder

	preprocess(recv128, s);

	load_bits(bits_int, sk + IRR_BYTES);
	benes(recv128, bits_int, 1);

	reformat_128to256(recv256, recv128);

	scaling(scaled, inv, sk, recv256, locator, eval, s_priv_cmp, buf);
	fft_tr(s_priv, scaled, buf);
	bm(locator, s_priv);

	fft(eval, locator, buf);

	// reencryption and weight check

	allone = vec256_set1_16b(0xFFFF);

	for (i = 0; i < 32; i++)
	{
		error256[i] = vec256_or_reduce(eval[i]);
		error256[i] = vec256_xor(error256[i], allone);
	}

	scaling_inv(scaled, inv, error256);
	fft_tr(s_priv_cmp, scaled, buf);

	check_synd = synd_cmp(s_priv, s_priv_cmp);

	//

	reformat_256to128(error128, error256);
	benes(error128, bits_int, 0);

	postprocess(e, error128);

	check_weight = weight_check(e, error128);

	return 1 - (check_synd & check_weight);
}

