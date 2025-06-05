#include "indcpa.h"
#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif
/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*              - uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk,
        uint8_t *sk,
        const uint8_t *coins) {
    PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(pk, sk, coins);
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_rkeypair_derand(const uint8_t *pk,
        uint8_t *rpk,
        uint8_t *rsk,
        const uint8_t *coins) {
    PQCLEAN_MLKEM512_CLEAN_indcpa_rkeypair_derand(pk, rpk, rsk, coins);
    memcpy(rsk + KYBER_INDCPA_SECRETKEYBYTES, rpk, KYBER_RPUBLICKEYBYTES);
    hash_h(rsk + KYBER_RSECRETKEYBYTES - 2 * KYBER_SYMBYTES, rpk, KYBER_RPUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(rsk + KYBER_RSECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk,
        uint8_t *sk) {
    uint8_t coins[2 * KYBER_SYMBYTES];
    randombytes(coins, 2 * KYBER_SYMBYTES);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);
    return 0;
}

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_rkeypair(const uint8_t *pk,
        uint8_t *rpk,
        uint8_t *rsk) {
    uint8_t coins[2 * KYBER_SYMBYTES];
    randombytes(coins, 2 * KYBER_SYMBYTES);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_rkeypair_derand(pk, rpk, rsk, coins);
    return 0;
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk,
        const uint8_t *rpk,
        const uint8_t *mu, const uint8_t *mur) {
    uint8_t buf[3 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];

    memcpy(buf, mu, KYBER_SYMBYTES);
    memcpy(buf + KYBER_SYMBYTES, mur, KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + 2 * KYBER_SYMBYTES, rpk, KYBER_RPUBLICKEYBYTES); // Hash rpk with the two messages
    hash_g(kr, buf, 3 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(ct, mu, mur, pk, rpk, kr + KYBER_SYMBYTES);

    memcpy(ss, kr, KYBER_SYMBYTES);
    return 0;
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk,
        const uint8_t *rpk) {
    uint8_t mu[KYBER_SYMBYTES], mur[KYBER_SYMBYTES];
    randombytes(mu, KYBER_SYMBYTES);
    randombytes(mur, KYBER_SYMBYTES);

    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, pk, rpk, mu, mur);
    return 0;
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss,
        const uint8_t *ct,
        const uint8_t *sk,
        const uint8_t *rsk) {
    int fail;
    uint8_t buf[3 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES + KYBER_SYMBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
    const uint8_t *rpk = rsk + KYBER_INDCPA_SECRETKEYBYTES;

    PQCLEAN_MLKEM512_CLEAN_indcpa_dec(buf, buf + KYBER_SYMBYTES, ct, sk, rsk);

    /* Multitarget countermeasure for coins + contributory KEM */
    memcpy(buf + 2 * KYBER_SYMBYTES, rsk + KYBER_RSECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES); // Hash rpk with the two message mu, mu_r
    hash_g(kr, buf, 3 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(cmp, buf, buf + KYBER_SYMBYTES, pk, rpk, kr + KYBER_SYMBYTES);

    fail = PQCLEAN_MLKEM512_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    /* Compute rejection key */
    rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, rsk + KYBER_RSECRETKEYBYTES - KYBER_SYMBYTES, rsk + KYBER_RSECRETKEYBYTES - 2 * KYBER_SYMBYTES, ct); // H_prf(s, s_r, rpk, ct)

    /* Copy true key to return buffer if fail is false */
    PQCLEAN_MLKEM512_CLEAN_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t) (1 - fail));

    return 0;
}
