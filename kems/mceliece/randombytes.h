#ifndef randombytes_H
#define randombytes_H

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/random.h>

// simply use get_random_bytes() from <linux/random.h>
#define randombytes(buf, size) get_random_bytes(buf, size)

#ifdef __cplusplus
}
#endif

#endif
