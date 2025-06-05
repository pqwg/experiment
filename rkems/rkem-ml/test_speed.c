//  test_main.c
//  Copyright (c) 2023 Plover Signature Team. See LICENSE.

//  === private tests and benchmarks

#ifndef NIST_KAT

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rkem.h"

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

static inline double cpu_clock_secs(void)
{
    return ((double)clock()) / ((double)CLOCKS_PER_SEC);
}

//  maximum message size
#define MAX_MSG 256

int main(void)
{
    size_t i;

    //  timing
    size_t iter = 100;
    double ts, to;
    uint64_t cc;

    //  buffers for serialized
    uint8_t pk[RKEM_STATIC_PUBLIC_KEY_BYTES] = {0};
    uint8_t sk[RKEM_STATIC_PRIVATE_KEY_BYTES] = {0};
    uint8_t rpk[RKEM_EPHEMERAL_PUBLIC_KEY_BYTES] = {0};
    uint8_t rsk[RKEM_EPHEMERAL_PRIVATE_KEY_BYTES] = {0};
    uint8_t ct[RKEM_CIPHERTEXT_BYTES] = {0};
    uint8_t ss[RKEM_SHARED_SECRET_BYTES] = {0};
    uint8_t ss2[RKEM_SHARED_SECRET_BYTES] = {0};

    //  (start)
    printf("RKEM_STATIC_PUBLIC_KEY_BYTES\t= %d\n", RKEM_STATIC_PUBLIC_KEY_BYTES);
    printf("RKEM_STATIC_PRIVATE_KEY_BYTES\t= %d\n", RKEM_STATIC_PRIVATE_KEY_BYTES);
    printf("RKEM_EPHEMERAL_PUBLIC_KEY_BYTES\t= %d\n", RKEM_EPHEMERAL_PUBLIC_KEY_BYTES);
    printf("RKEM_EPHEMERAL_PRIVATE_KEY_BYTES\t= %d\n", RKEM_EPHEMERAL_PRIVATE_KEY_BYTES);
    printf("RKEM_CIPHERTEXT_BYTES\t= %d\n", RKEM_CIPHERTEXT_BYTES);
    printf("RKEM_SHARED_SECRET_BYTES\t= %d\n", RKEM_SHARED_SECRET_BYTES);

    //  === keygen ===
    assert(rkem_static_keygen(pk, sk) == 0);
    assert(rkem_ephemeral_keygen(rpk, rsk, pk, NULL) == 0);
    assert(rkem_encapsulate(ss, ct, pk, rpk, NULL) == 0);
    assert(rkem_decapsulate(ss2, ct, sk, rsk, NULL) == 0);

    assert(0 == memcmp(ss, ss2, RKEM_SHARED_SECRET_BYTES));

#ifdef BENCH_TIMEOUT
    to = BENCH_TIMEOUT;
#else
    to = 1.0;  //   timeout threshold (seconds)
#endif

    printf("=== Bench ===\n");

    iter = 16;
    do {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++) {
            rkem_static_keygen(pk, sk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("KeyGen() %5zu:\t%8.3f ms\t%8.3f Kcyc\n", iter,
           1000.0 * ts / ((double)iter), 1E-3 * ((double) (cc / iter)));

    iter = 16;
    do
    {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            rkem_ephemeral_keygen(rpk, rsk, pk, NULL);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("RKeyGen() %5zu:\t%8.3f ms\t%8.3f Kcyc\n", iter,
           1000.0 * ts / ((double)iter), 1E-3 * ((double)(cc / iter)));

    iter = 16;
    do
    {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++)
        {
            rkem_encapsulate(ss, ct, pk, rpk, NULL);
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
            rkem_decapsulate(ss2, ct, sk, rsk, NULL);
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
