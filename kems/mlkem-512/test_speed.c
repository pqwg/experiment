//  test_main.c
//  Copyright (c) 2023 Plover Signature Team. See LICENSE.

//  === private tests and benchmarks

#ifndef NIST_KAT

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "api.h"

//  get cycle counts

static inline uint64_t plat_get_cycle()
{

#if defined(__i386__) || defined(__x86_64__)

    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (((uint64_t)hi) << 32) | ((uint64_t)lo);

#else

    //  ARM cycle counts may not be available in userland
    return 0;
#endif

}

//  standard library process time

static inline double cpu_clock_secs()
{
    return ((double)clock()) / ((double)CLOCKS_PER_SEC);
}

//  maximum message size
#define MAX_MSG 256

int main()
{
    size_t i;

    //  timing
    size_t iter = 100;
    double ts, to;
    uint64_t cc;

    //  buffers for serialized
    uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES] = {0};
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES] = {0};
    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES] = {0};
    uint8_t ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES] = {0};

    //  (start)
    printf("PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES\t= %d\n", PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES\t= %d\n", PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES\t= %d\n", PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    printf("PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES\t= %d\n", PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);

    //  === keygen ===
    assert(PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk) == 0);
    assert(PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk) == 0);
    assert(PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk) == 0);

    assert(0 == memcmp(ss, ss2, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES));

#ifdef BENCH_TIMEOUT
    to = BENCH_TIMEOUT;
#else
    to = 1.0; //   timeout threshold (seconds)
#endif

    printf("=== Bench ===\n");

    iter = 16;
    do
    {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("KeyGen() %5zu:\t%8.3f ms\t%8.3f Kcyc\n", iter,
           1000.0 * ts / ((double)iter), 1E-3 * ((double)(cc / iter)));

    iter = 16;
    do
    {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("Encaps() %5zu:\t%8.3f ms\t%8.3f Kcyc\n", iter,
           1000.0 * ts / ((double)iter), 1E-3 * ((double)(cc / iter)));

    iter = 16;
    do
    {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("Decaps() %5zu:\t%8.3f ms\t%8.3f Kcyc\n", iter,
           1000.0 * ts / ((double)iter), 1E-3 * ((double)(cc / iter)));

    return 0;
}

// NIST_KAT
#endif
