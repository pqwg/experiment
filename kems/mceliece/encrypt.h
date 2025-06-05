/*
  This file is for Niederreiter encryption
*/

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "params.h"
#include "mcbuf.h"

#define TWISTED_PRF_KEY_LEN 32

void encrypt(unsigned char *s, const unsigned char *pk, unsigned char *e,
             const u8 key1[TWISTED_PRF_KEY_LEN],
             const u8 key2[TWISTED_PRF_KEY_LEN],
             struct mc_buffer* const buf);
#endif
