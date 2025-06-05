/*
  This file is for matrix transposition
*/

#ifndef TRANSPOSE_H
#define TRANSPOSE_H

#include "vec128.h"
#include "vec256.h"

extern void transpose_64x128_sp_asm(vec128 *);

#define transpose_64x128_sp(in) transpose_64x128_sp_asm((in))

extern void transpose_64x256_sp_asm(vec256 *);

#define transpose_64x256_sp(in) transpose_64x256_sp_asm((in))

#endif


