#ifndef PQCLEAN_MLKEM512_CLEAN_PARAMS_H
#define PQCLEAN_MLKEM512_CLEAN_PARAMS_H



/* Don't change parameters below this line */

#define KYBER_N 256
#define KYBER_Q 10753

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES     448
#define KYBER_POLYVECKBYTES  (KYBER_K * KYBER_POLYBYTES)
#define KYBER_POLYVECELLBYTES  (KYBER_ELL * KYBER_POLYBYTES)

#define KYBER_K 3
#define KYBER_ELL 2
#define KYBER_ETA1 3
#define KYBER_CTSTATICBYTES 96
#define KYBER_CTEPHBYTES 224
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_ELL * 384)
#define KYBER_RPK_COMPRESSEDBYTES    (KYBER_K * 288)

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECKBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_RPUBLICKEYBYTES KYBER_RPK_COMPRESSEDBYTES
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECELLBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_CTSTATICBYTES + KYBER_CTEPHBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_RPUBLICKEYBYTES (KYBER_INDCPA_RPUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_RSECRETKEYBYTES (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_RPUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#endif
