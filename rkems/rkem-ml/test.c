#include "rkem.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  printf("pk size %d\n", RKEM_STATIC_PUBLIC_KEY_BYTES);
  printf("sk size %d\n", RKEM_STATIC_PRIVATE_KEY_BYTES);
  printf("rpk size %d\n", RKEM_EPHEMERAL_PUBLIC_KEY_BYTES);
  printf("rsk size %d\n", RKEM_EPHEMERAL_PRIVATE_KEY_BYTES);
  printf("ct size %d\n", RKEM_CIPHERTEXT_BYTES);

  for (int i = 0; i < 1000; i++) {
    uint8_t *pk, *sk, *rpk, *rsk, *ct, *ss1, *ss2;
    pk = malloc(RKEM_STATIC_PUBLIC_KEY_BYTES);
    sk = malloc(RKEM_STATIC_PRIVATE_KEY_BYTES);
    rpk = malloc(RKEM_EPHEMERAL_PUBLIC_KEY_BYTES);
    rsk = malloc(RKEM_EPHEMERAL_PRIVATE_KEY_BYTES);
    ct = malloc(RKEM_CIPHERTEXT_BYTES);
    ss1 = malloc(RKEM_SHARED_SECRET_BYTES);
    ss2 = malloc(RKEM_SHARED_SECRET_BYTES);

    if (!pk || !sk || !rpk || !rsk || !ct || !ss1 || !ss2) {
      fprintf(stderr, "Memory allocation failed\n");
      exit(EXIT_FAILURE);
    }

    memset(ss1, 0, RKEM_SHARED_SECRET_BYTES);
    memset(ss2, 0xFF, RKEM_SHARED_SECRET_BYTES);

    assert(rkem_static_keygen(pk, sk) == 0);
    assert(rkem_ephemeral_keygen(rpk, rsk, pk, NULL) == 0);
    assert(rkem_encapsulate(ss1, ct, pk, rpk, NULL) == 0);
    assert(rkem_decapsulate(ss2, ct, sk, rsk, NULL) == 0);

#ifdef PRINT_DEBUG
    for (size_t i = 0; i < RKEM_SHARED_SECRET_BYTES; ++i) {
      printf("%02x", (unsigned int)ss1[i]);
    }
    printf(" ");
    for (size_t i = 0; i < RKEM_SHARED_SECRET_BYTES; ++i) {
      printf("%02x", (unsigned int)ss2[i]);
    }
    printf("\n");
#endif

    assert(0 == memcmp(ss1, ss2, RKEM_SHARED_SECRET_BYTES));

    free(pk);
    free(sk);
    free(rpk);
    free(rsk);
    free(ct);
    free(ss1);
    free(ss2);
  }

  puts("Done!");
}
