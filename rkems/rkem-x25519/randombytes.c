#ifdef __KERNEL__
#include <linux/random.h>
#else
#include <sys/random.h>
#endif


#include "randombytes.h"

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
int randombytes(uint8_t *output, size_t n) {
#ifdef __KERNEL__
  return get_random_bytes_wait(output, n);
#else
  return getrandom(output, n, 0);
#endif
}


