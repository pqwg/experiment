/*
  This file is for the Gao-Mateer FFT
  sse http://www.math.clemson.edu/~sgao/papers/GM10.pdf
*/

#ifndef MC_KERN_FFT_H
#define MC_KERN_FFT_H

#include <linux/types.h>
#include "params.h"
#include "vec128.h"
#include "vec256.h"
#include "mcbuf.h"

void fft(vec256 [][GFBITS], vec128 *, struct mc_buffer* const);

#endif

