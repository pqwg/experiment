#include "ntt.h"
#include "params.h"
#include "reduce.h"

// Generated with scripts/ntt.sage
static const int16_t zetas[256] = {
  0, 223, 4188, -3688, 2413, -3686, 357, -376, 2695, -730, 4855, 2236, -425, 4544, 3364, -3784, 4875, -1520, -5063, -4035, 2503, 918, -3012, 4347, 1931, -1341, -3823, -341, -4095, -5175, -2629, -5213, -3091, 4129, -2935, 2790, 268, 1284, 4, 3550, 2982, 1287, 205, 4513, -2565, -2178, 4616, -193, -4102, 4742, -4876, -4744, -2984, -3062, -847, -4379, -2388, -1009, -3085, -1299, -2576, 4189, 1085, 544, 5023, 794, -567, -3198, 4734, -2998, 3441, -5341, 675, 2271, 1615, -2213, 512, 2774, 3057, -2045, 3615, -1458, -909, 5114, 2981, -4977, -116, 4580, -454, -5064, 4808, -1841, -886, -1356, -4828, -5156, 2737, 4286, -3169, -578, 5294, -636, 400, 151, -2884, -336, -1006, -326, 1572, -2740, -779, 2206, -1586, 1068, -3715, -1268, 2684, -5116, 1324, 2973, -2234, -4123, 3337, -864, 472, -467, 970, 635, -573, 2230, -1132, -4621, 2624, -4601, 3570, -3760, -5309, 3453, -5215, 854, -4250, 2428, 1381, 5172, -5015, -4447, 3135, 2662, 3524, -1573, 2139, 458, -2196, -2657, 4782, -3410, 2062, 2015, -4784, 1635, 1349, -1722, 2909, -4359, 2680, 2087, 40, 3241, -2439, 2117, 2050, 2118, -4144, -274, 3148, -1930, 1992, 4408, 5005, -4428, 2419, 1639, 2283, -778, -2374, 663, 1409, -2237, -4254, -1122, 97, -5313, -3535, -2813, 5083, 279, 4328, 2279, 2151, 355, -4003, 1204, -5356, -624, 5120, -4519, -1689, 1056, 3891, -3827, 1663, -2625, -2449, 3995, -1160, 2788, -4540, 3125, 5068, 3096, 1893, -2807, -5268, 2205, -4889, -152, 569, 4973, -825, 4393, 4000, 1510, 3419, -3360, 693, -3260, 4967, 4859, 2963, 554, -5107, -73, -4891, -1927, 5334, 2605, 2487, -2529, -834, 1782, 1111, 2113, 4720, -4670, -1053, -4403
};

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - int16_t a: first factor
*              - int16_t b: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/
static int16_t fqmul(int16_t a, int16_t b) {
    return PQCLEAN_MLKEM512_CLEAN_montgomery_reduce((int32_t)a * b);
}

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_ntt(int16_t r[256]) {
  unsigned int len, start, j, k;
  int16_t zeta, t;

  k = 0;
  for(len = 128; len > 0; len >>= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas[++k];
      for(j = start; j < start + len; ++j) {
        t = fqmul(zeta, r[j + len]);
        r[j + len] = PQCLEAN_MLKEM512_CLEAN_barrett_reduce(r[j] - t);
        r[j] = PQCLEAN_MLKEM512_CLEAN_barrett_reduce(r[j] + t);
      }
    }
  }
}

/*************************************************
* Name:        invntt_tomont
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_invntt(int16_t r[256])
{
  unsigned int start, len, j, k;
  int16_t t, zeta;
  const int16_t f = 2536; // r^2/256

  k = 256;
  for (len = 1; len < 256; len <<= 1)
  {
    for (start = 0; start < 256; start = j + len)
    {
      zeta = -zetas[--k];
      for (j = start; j < start + len; ++j)
      {
        t = r[j];
        r[j] = PQCLEAN_MLKEM512_CLEAN_barrett_reduce(t + r[j + len]);
        r[j + len] = t - r[j + len];
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }
  }

  for (j = 0; j < 256; ++j)
  {
    r[j] = fqmul(f, r[j]);
  }
}

/*************************************************
 * Name:        PQCLEAN_MLKEM512_CLEAN_basemul
 *
 * Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
 *              used for multiplication of elements in Rq in NTT domain
 *
 * Arguments:   - int16_t r[2]: pointer to the output polynomial
 *              - const int16_t a[2]: pointer to the first factor
 *              - const int16_t b[2]: pointer to the second factor
 *              - int16_t zeta: integer defining the reduction polynomial
 **************************************************/
void PQCLEAN_MLKEM512_CLEAN_basemul(int16_t r[256], const int16_t a[256], const int16_t b[256])
{
  for (int i = 0; i < 256; i++)
  {
    r[i] = fqmul(a[i], b[i]);
  }
}
