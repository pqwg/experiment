#include "vec128.h"

void vec128_copy(vec128 *dest, vec128 *src)
{
	int i;

	for (i = 0; i < GFBITS; i++)
		dest[i] = src[i];
}

void vec128_add(vec128 *c, vec128 *a, vec128 *b)
{
	int i;

	for (i = 0; i < GFBITS; i++)
		c[i] = vec128_xor(a[i], b[i]);
}

vec128 vec128_or_reduce(vec128 * a) 
{
	int i;
	vec128 ret;		

	ret = a[0];
	for (i = 1; i < GFBITS; i++)
		ret = vec128_or(ret, a[i]);

	return ret;
}

/* bitsliced field multiplications */
void vec128_mul(vec128 *h, vec128 *f, const vec128 *g)
{
        vec128_mul_asm(h, f, g, 16);
}
