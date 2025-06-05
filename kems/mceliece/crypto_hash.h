#include "fips202.h"

#define crypto_hash_32b(out,in,inlen) \
  shake256(out, 32, in, inlen)
