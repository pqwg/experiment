#include "indcpa.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"
#include "gauss_sample.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvecK *pk,
                    const uint8_t seed[KYBER_SYMBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvecK_tobytes(r, pk);
    memcpy(r + KYBER_POLYVECKBYTES, seed, KYBER_SYMBYTES);
}
static void pack_rpk(uint8_t r[KYBER_INDCPA_RPUBLICKEYBYTES],
                    polyvecK *rpk) {
    PQCLEAN_MLKEM512_CLEAN_polyvecK_compress(r, rpk);
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvecK *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvecK_frombytes(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECKBYTES, KYBER_SYMBYTES);
}

static void unpack_rpk(polyvecK *rpk,
                      const uint8_t packedrpk[KYBER_INDCPA_RPUBLICKEYBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvecK_randdecompress(rpk, packedrpk);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvecEll *sk) {
    PQCLEAN_MLKEM512_CLEAN_polyvecEll_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvecEll *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvecEll_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], const polyvecEll *b, const poly *vstatic, const poly *veph, const uint8_t cteph_mask[KYBER_CTEPHBYTES])
{
    PQCLEAN_MLKEM512_CLEAN_polyvecEll_compress(r, b);
    PQCLEAN_MLKEM512_CLEAN_poly_compress_static(r + KYBER_POLYVECCOMPRESSEDBYTES, vstatic);
    PQCLEAN_MLKEM512_CLEAN_poly_compress_ephemeral(r + KYBER_POLYVECCOMPRESSEDBYTES + KYBER_CTSTATICBYTES, veph);
    // Mask ephemeral ciphertext
    for (int i = 0; i < KYBER_CTEPHBYTES; i++) {
        r[KYBER_POLYVECCOMPRESSEDBYTES + KYBER_CTSTATICBYTES + i] ^= cteph_mask[i];
    }
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext_static(polyvecEll *b, poly *vstatic, const uint8_t c[KYBER_INDCPA_BYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvecEll_decompress(b, c);
    PQCLEAN_MLKEM512_CLEAN_poly_decompress_static(vstatic, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

static void unpack_ciphertext_ephemeral(poly *veph, const uint8_t c[KYBER_INDCPA_BYTES], const uint8_t cteph_mask[KYBER_CTEPHBYTES])
{
    uint8_t unmasked_cteph[KYBER_CTEPHBYTES];
    for (int i = 0; i < KYBER_CTEPHBYTES; i++) {
        unmasked_cteph[i] = c[KYBER_POLYVECCOMPRESSEDBYTES + KYBER_CTSTATICBYTES + i] ^ cteph_mask[i];
    }
    PQCLEAN_MLKEM512_CLEAN_poly_decompress_ephemeral(veph, unmasked_cteph);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos, j;
    uint16_t val[4];

    ctr = pos = 0;
    while (ctr < len && pos + 7 <= buflen)
    {
        val[0] = (buf[0] >> 0) | ((uint16_t)buf[1] << 8);
        val[1] = (buf[1] >> 6) | ((uint16_t)buf[2] << 2) | ((uint16_t)buf[3] << 10);
        val[2] = (buf[3] >> 4) | ((uint16_t)buf[4] << 4) | ((uint16_t)buf[5] << 12);
        val[3] = (buf[5] >> 2) | ((uint16_t)buf[6] << 6);

        pos += 7;

        for (j = 0; j < 4; j++) {
            val[j] &= 16383;
            if (ctr < len && val[j] < KYBER_Q) {
                r[ctr++] = val[j];
            }
        }
    }

    return ctr;
}

#define gen_a(A,B)  PQCLEAN_MLKEM512_CLEAN_gen_matrix(A,B)
#define gen_at(A,B) PQCLEAN_MLKEM512_CLEAN_gen_matrix_t(A,B)

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 14)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvecEll *a, const uint8_t seed[KYBER_SYMBYTES]) {
    unsigned int ctr, i, j;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_ELL; j++) {
            xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

            while (ctr < KYBER_N) {
                xof_squeezeblocks(buf, 1, &state);
                buflen = XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
            }
            xof_ctx_release(&state);
        }
    }
}
void PQCLEAN_MLKEM512_CLEAN_gen_matrix_t(polyvecK *at, const uint8_t seed[KYBER_SYMBYTES]) {
    unsigned int ctr, i, j;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    for (i = 0; i < KYBER_ELL; i++) {
        for (j = 0; j < KYBER_K; j++) {
            xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(at[i].vec[j].coeffs, KYBER_N, buf, buflen);

            while (ctr < KYBER_N) {
                xof_squeezeblocks(buf, 1, &state);
                buflen = XOF_BLOCKBYTES;
                ctr += rej_uniform(at[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
            }
            xof_ctx_release(&state);
        }
    }
}

static void gen_matrix_element(poly *a, const uint8_t seed[KYBER_SYMBYTES], unsigned int i, unsigned int j) {
    unsigned int buflen, ctr;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);

    xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
    buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
    ctr = rej_uniform(a->coeffs, KYBER_N, buf, buflen);

    while (ctr < KYBER_N) {
        xof_squeezeblocks(buf, 1, &state);
        buflen = XOF_BLOCKBYTES;
        ctr += rej_uniform(a->coeffs + ctr, KYBER_N - ctr, buf, buflen);
    }
    xof_ctx_release(&state);
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i, j;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvecEll skpv;
    polyvecK pkpv;
    poly aEl, e;

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = KYBER_K;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    for (i = 0; i < KYBER_ELL; i++) {
        sample_sk_poly(&skpv.vec[i], noiseseed, nonce++);
    }

    PQCLEAN_MLKEM512_CLEAN_polyvecEll_ntt(&skpv);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++) {
        poly t;

        gen_matrix_element(&aEl, publicseed, i, 0);
        PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&pkpv.vec[i], &skpv.vec[0], &aEl);
        for (j = 1; j < KYBER_ELL; j++) {
            gen_matrix_element(&aEl, publicseed, i, j);
            PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&t, &skpv.vec[j], &aEl);
            PQCLEAN_MLKEM512_CLEAN_poly_add(&pkpv.vec[i], &pkpv.vec[i], &t);
        }
        PQCLEAN_MLKEM512_CLEAN_poly_reduce(&pkpv.vec[i]);
    }

    // contrary to Kyber, as we compress rpk, we do not store public keys in NTT domain
    PQCLEAN_MLKEM512_CLEAN_polyvecK_invntt_tomont(&pkpv);

    // Sample and add MLWE error
    for (i = 0; i < KYBER_K; i++) {
        sample_sk_poly(&e, noiseseed, nonce++);
        PQCLEAN_MLKEM512_CLEAN_poly_add(&pkpv.vec[i], &pkpv.vec[i], &e);
    }
    PQCLEAN_MLKEM512_CLEAN_polyvecK_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

void PQCLEAN_MLKEM512_CLEAN_indcpa_rkeypair_derand(const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t rpk[KYBER_INDCPA_RPUBLICKEYBYTES],
        uint8_t rsk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i, j;
    const uint8_t *publicseed = pk + KYBER_POLYVECKBYTES;
    const uint8_t *noiseseed = coins;
    uint8_t nonce = 0;
    polyvecEll skpv;
    polyvecK pkpv;
    poly aEl, e;

    for (i = 0; i < KYBER_ELL; i++) {
        sample_sk_poly(&skpv.vec[i], noiseseed, nonce++);
    }

    PQCLEAN_MLKEM512_CLEAN_polyvecEll_ntt(&skpv);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++) {
        poly t;

        gen_matrix_element(&aEl, publicseed, i, 0);
        PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&pkpv.vec[i], &skpv.vec[0], &aEl);
        for (j = 1; j < KYBER_ELL; j++) {
            gen_matrix_element(&aEl, publicseed, i, j);
            PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&t, &skpv.vec[j], &aEl);
            PQCLEAN_MLKEM512_CLEAN_poly_add(&pkpv.vec[i], &pkpv.vec[i], &t);
        }
        PQCLEAN_MLKEM512_CLEAN_poly_reduce(&pkpv.vec[i]);
    }

    // contrary to Kyber, as we compress rpk, we do not store public keys in NTT domain
    PQCLEAN_MLKEM512_CLEAN_polyvecK_invntt_tomont(&pkpv);

    // Sample and add MLWE error
    for (i = 0; i < KYBER_K; i++) {
        sample_sk_poly(&e, noiseseed, nonce++);
        PQCLEAN_MLKEM512_CLEAN_poly_add(&pkpv.vec[i], &pkpv.vec[i], &e);
    }
    PQCLEAN_MLKEM512_CLEAN_polyvecK_reduce(&pkpv);

    pack_sk(rsk, &skpv);
    pack_rpk(rpk, &pkpv);
}


/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t mu[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t mur[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                       const uint8_t rpk[KYBER_INDCPA_RPUBLICKEYBYTES],
                                       const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i, j;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvecK sp, pkpv;
    polyvecEll b;
    poly vstatic, veph, k, aEl, e;
    uint8_t delta[KYBER_CTEPHBYTES];

    unpack_pk(&pkpv, seed, pk);
    PQCLEAN_MLKEM512_CLEAN_polyvecK_ntt(&pkpv);

    for (i = 0; i < KYBER_K; i++) {
        sample_r_poly(sp.vec + i, coins, nonce++);
    }

    PQCLEAN_MLKEM512_CLEAN_polyvecK_ntt(&sp);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_ELL; i++) {
        poly t;

        // Tranpose of public matrix A
        gen_matrix_element(&aEl, seed, 0, i);
        PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&b.vec[i], &sp.vec[0], &aEl);
        for (j = 1; j < KYBER_K; j++) {
            gen_matrix_element(&aEl, seed, j, i);
            PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&t, &sp.vec[j], &aEl);
            PQCLEAN_MLKEM512_CLEAN_poly_add(&b.vec[i], &b.vec[i], &t);
        }
        PQCLEAN_MLKEM512_CLEAN_poly_reduce(&b.vec[i]);
    }

    PQCLEAN_MLKEM512_CLEAN_polyvecEll_invntt_tomont(&b);
    // Sample and add MLWE error
    for (i = 0; i < KYBER_ELL; i++)
    {
        sample_r_poly(&e, coins, nonce++);
        PQCLEAN_MLKEM512_CLEAN_poly_add(&b.vec[i], &b.vec[i], &e);
    }
    PQCLEAN_MLKEM512_CLEAN_polyvecEll_reduce(&b);

    // Sample static ciphertext
    sample_noise_poly(&e, coins, nonce++);
    PQCLEAN_MLKEM512_CLEAN_polyvecK_basemul_acc_montgomery(&vstatic, &pkpv, &sp);

    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&vstatic);

    PQCLEAN_MLKEM512_CLEAN_poly_add(&vstatic, &vstatic, &e);

    PQCLEAN_MLKEM512_CLEAN_poly_frommsg(&k, mu);
    PQCLEAN_MLKEM512_CLEAN_poly_add(&vstatic, &vstatic, &k);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&vstatic);

    // Sample ephemeral ciphertext
    sample_r_poly(&e, coins, nonce++);

    unpack_rpk(&pkpv, rpk);
    PQCLEAN_MLKEM512_CLEAN_polyvecK_ntt(&pkpv);
    PQCLEAN_MLKEM512_CLEAN_polyvecK_basemul_acc_montgomery(&veph, &pkpv, &sp);

    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&veph);

    PQCLEAN_MLKEM512_CLEAN_poly_add(&veph, &veph, &e);

    PQCLEAN_MLKEM512_CLEAN_poly_frommsg(&k, mur);
    PQCLEAN_MLKEM512_CLEAN_poly_add(&veph, &veph, &k);

    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&veph);

    prf(delta, KYBER_CTEPHBYTES, mu, 'd');
    pack_ciphertext(c, &b, &vstatic, &veph, delta);

}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_indcpa_dec(uint8_t mu[KYBER_INDCPA_MSGBYTES], uint8_t mur[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                                       const uint8_t rsk[KYBER_INDCPA_SECRETKEYBYTES])
{
    polyvecEll b, skpv, rskpv;
    poly vstatic, veph, mp;
    uint8_t delta[KYBER_CTEPHBYTES];

    unpack_ciphertext_static(&b, &vstatic, c);
    unpack_sk(&skpv, sk);
    unpack_sk(&rskpv, rsk);

    PQCLEAN_MLKEM512_CLEAN_polyvecEll_ntt(&b);

    // Decrypt static ciphertext
    PQCLEAN_MLKEM512_CLEAN_polyvecEll_basemul_acc_montgomery(&mp, &skpv, &b);
    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&mp);

    PQCLEAN_MLKEM512_CLEAN_poly_sub(&mp, &vstatic, &mp);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&mp);

    PQCLEAN_MLKEM512_CLEAN_poly_tomsg(mu, &mp);

    // Decrypt ephemeral ciphertext
    prf(delta, KYBER_CTEPHBYTES, mu, 'd');
    unpack_ciphertext_ephemeral(&veph, c, delta);

    PQCLEAN_MLKEM512_CLEAN_polyvecEll_basemul_acc_montgomery(&mp, &rskpv, &b);
    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&mp);

    PQCLEAN_MLKEM512_CLEAN_poly_sub(&mp, &veph, &mp);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&mp);

    PQCLEAN_MLKEM512_CLEAN_poly_tomsg(mur, &mp);
}
