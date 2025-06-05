/*
  This file is for Niederreiter decryption
*/

#ifndef DECRYPT_H
#define DECRYPT_H

#include "mcbuf.h"

int decrypt(unsigned char *, const unsigned char *, const unsigned char *,
            struct mc_buffer* const buf);

#endif

