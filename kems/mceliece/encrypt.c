/*
  This file is for Niederreiter encryption
*/

#include "encrypt.h"

#include "gf.h"
#include "util.h"
#include "params.h"
#include "int32_sort.h"
#include "randombytes.h"

#include <crypto/blake2s.h>
#include <linux/random.h>
#include <linux/types.h>
#include <crypto/algapi.h> // For crypto_xor_cpy.


/* input: public key pk, error vector e */
/* output: syndrome s */
extern void syndrome_asm(unsigned char *s, const unsigned char *pk, unsigned char *e);

static void
twisted_prf_gen(u8* const __restrict__ out,
                u8* const __restrict__ tmp,
                const int out_len,
                const u8 key1[TWISTED_PRF_KEY_LEN],
                const u8 key2[TWISTED_PRF_KEY_LEN]) {
    // sample one random value from the untrusted RNG
    //u8 rnd_seed[32];
    // and a salt. this salt does not need to be kept secret
    //u8 salt[32];

    get_random_bytes(out, out_len);

}

/* output: e, an error vector of weight t */
static void gen_e(unsigned char *e,
                  const u8 key1[TWISTED_PRF_KEY_LEN],
                  const u8 key2[TWISTED_PRF_KEY_LEN],
                  struct mc_buffer* const buf)
{
	int i, j, eq, count;

        // NOTE: pretty close to the kernel stack limit
        // there's not much space left for temporary vars
        uint64_t val[SYS_T];

        union {
            uint16_t ind[SYS_T*2];
            uint64_t e_int[ (SYS_N+63)/64 ];
        } eind_store;

        union {
            uint16_t ind_tmp[SYS_T*2];
            int32_t ind32[SYS_T*2];
        } int_store;

	uint64_t one = 1;
	uint64_t mask;

	while (1)
	{
                twisted_prf_gen((unsigned char*) eind_store.ind,
                                (unsigned char*) int_store.ind_tmp,
                                sizeof(uint16_t)*SYS_T*2, key1, key2);

		for (i = 0; i < SYS_T*2; i++)
			eind_store.ind[i] &= GFMASK;

		// moving and counting indices in the correct range

		count = 0;
		for (i = 0; i < SYS_T*2; i++)
			if (eind_store.ind[i] < SYS_N)
				int_store.ind32[ count++ ] = eind_store.ind[i];
		
		if (count < SYS_T) continue;

		// check for repetition

		int32_sort(int_store.ind32, SYS_T);

		eq = 0;
		for (i = 1; i < SYS_T; i++)
			if (int_store.ind32[i-1] == int_store.ind32[i])
				eq = 1;

		if (eq == 0)
			break;
	}

	for (j = 0; j < SYS_T; j++)
		val[j] = one << (int_store.ind32[j] & 63);

	for (i = 0; i < (SYS_N+63)/64; i++) 
	{
		eind_store.e_int[i] = 0;

		for (j = 0; j < SYS_T; j++)
		{
			mask = i ^ (int_store.ind32[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = -mask;

			eind_store.e_int[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < (SYS_N+63)/64; i++) 
		{ store8(e, eind_store.e_int[i]); e += 8; }
}

/* input: public key pk */
/* output: error vector e, syndrome s */
void encrypt(unsigned char *s, const unsigned char *pk, unsigned char *e,
             const u8 key1[TWISTED_PRF_KEY_LEN],
             const u8 key2[TWISTED_PRF_KEY_LEN],
             struct mc_buffer* const buf)
{
	gen_e(e, key1, key2, buf);
	syndrome_asm(s, pk, e);
}

