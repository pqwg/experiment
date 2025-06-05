#include "kem.h"
#include <stdio.h>


int main(void) {

	u8 pk[KEM_PUBLIC_KEY_SIZE], sk[KEM_PRIVATE_KEY_SIZE];
	u8 ct[KEM_CIPHERTEXT_SIZE];
	u8 ss1[32], ss2[32];

	printf("KEM public key size:  %d\n", KEM_PUBLIC_KEY_SIZE);
	printf("KEM private key size: %d\n", KEM_PRIVATE_KEY_SIZE);
	printf("KEM ciphertext size:  %d\n", KEM_CIPHERTEXT_SIZE);


	struct kem_buffer buf;

	kem_keygen(pk, sk, &buf);

	kem_encapsulate(ss1, ct, pk, &buf);
	kem_decapsulate(ss2, ct, sk, &buf);

	for (int i = 0; i < 32; i++) { 
	   if (ss1[i] != ss2[i]) {
		   printf("Unequal at index %d\n", i);
		   return 1;
	   }
	}


	return 0;
}
