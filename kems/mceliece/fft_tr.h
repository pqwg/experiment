/*
  This file is for transpose of the Gao-Mateer FFT
*/

#ifndef FFT_TR_H
#define FFT_TR_H

#include "params.h"
#include "vec256.h"
#include "mcbuf.h"

void fft_tr(vec256 *, vec256 [][ GFBITS ], struct mc_buffer* const buf);

#endif

