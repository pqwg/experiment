#include "SABER_indcpa.h"
#include "fips202.h" // sha256 and sha512
#include "saber.h"

/* take a random coin, generate a secret and encapsulate it */
// TODO: generate the the random seed instead of taking it as a param */
void saber_indcpa_enc(unsigned char* ct, unsigned char *ss,
                      const unsigned char *pk,
                      unsigned char coins[SABER_KEYBYTES+SABER_NOISESEEDBYTES], // 64 bytes
                      struct eph_buffer* const ebuf) {
    /* Don't release system RNG output */
    sha3_512(coins, coins, SABER_NOISESEEDBYTES);
    // the first SABER_KEYBYTES (32) is the pre-k
    // the last SABER_NOISESEEDBYTES (32) is the coin
    indcpa_kem_enc(coins, coins + SABER_KEYBYTES, pk, ct, ebuf);
    // the shared key is the hash value of pre-k
    sha3_256(ss, coins, SABER_KEYBYTES);
}

void saber_indcpa_dec(unsigned char *ss, const unsigned char *ct,
                      const unsigned char *sk, struct eph_buffer* const ebuf) {
    // decrypt pre-k
    indcpa_kem_dec(sk, ct, ss, ebuf);
    // the shared key is the hash value of pre-k
    sha3_256(ss, ss, SABER_KEYBYTES);
}
