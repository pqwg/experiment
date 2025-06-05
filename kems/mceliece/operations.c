#include "operations.h"

#include "randombytes.h"
#include "crypto_hash.h"
#include "encrypt.h"
#include "decrypt.h"
#include "params.h"
#include "util.h"

#include <linux/types.h>

int crypto_kem_mceliece460896_avx_enc(
       unsigned char *c,
       unsigned char *key,
       const unsigned char *pk,
       const unsigned char key1[TWISTED_PRF_KEY_LEN],
       const unsigned char key2[TWISTED_PRF_KEY_LEN],
       struct mc_buffer* const buf
)
{
	unsigned char two_e[ 1 + SYS_N/8 ] = {2};
	unsigned char *e = two_e + 1;
	unsigned char one_ec[ 1 + SYS_N/8 + (SYND_BYTES + 32) ] = {1};

	//

	encrypt(c, pk, e, key1, key2, buf);

	crypto_hash_32b(c + SYND_BYTES, two_e, sizeof(two_e)); 

	memcpy(one_ec + 1, e, SYS_N/8);
	memcpy(one_ec + 1 + SYS_N/8, c, SYND_BYTES + 32);

	crypto_hash_32b(key, one_ec, sizeof(one_ec));

	return 0;
}

int crypto_kem_mceliece460896_avx_dec(
       unsigned char *key,
       const unsigned char *c,
       const unsigned char *sk,
       struct mc_buffer* const buf
)
{
	int i;

	unsigned char ret_confirm = 0;
	unsigned char ret_decrypt = 0;

	uint16_t m;

	unsigned char conf[32];
	unsigned char two_e[ 1 + SYS_N/8 ] = {2};
	unsigned char *e = two_e + 1;
	unsigned char preimage[ 1 + SYS_N/8 + (SYND_BYTES + 32) ];
	unsigned char *x = preimage;

	//

	ret_decrypt = decrypt(e, sk + SYS_N/8, c, buf);

	crypto_hash_32b(conf, two_e, sizeof(two_e)); 

	for (i = 0; i < 32; i++) ret_confirm |= conf[i] ^ c[SYND_BYTES + i];

	m = ret_decrypt | ret_confirm;
	m -= 1;
	m >>= 8;

	                                      *x++ = (~m &     0) | (m &    1);
	for (i = 0; i < SYS_N/8;         i++) *x++ = (~m & sk[i]) | (m & e[i]);
	for (i = 0; i < SYND_BYTES + 32; i++) *x++ = c[i];

	crypto_hash_32b(key, preimage, sizeof(preimage)); 

	return 0;
}
