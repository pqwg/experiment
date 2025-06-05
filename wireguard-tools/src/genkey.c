// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "kem/kem.h"
#include "linux/wireguard.h"
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#ifndef MAC_OS_X_VERSION_10_12
#define MAC_OS_X_VERSION_10_12 101200
#endif
#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12
#include <sys/random.h>
#endif
#endif

#include "encoding.h"
#include "subcommands.h"

#ifndef _WIN32
static inline bool __attribute__((__warn_unused_result__)) get_random_bytes(uint8_t *out, size_t len)
{
	ssize_t ret = 0;
	size_t i;
	int fd;

	if (len > 256) {
		errno = EOVERFLOW;
		return false;
	}

#if defined(__OpenBSD__) || (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
	if (!getentropy(out, len))
		return true;
#endif

#if defined(__NR_getrandom) && defined(__linux__)
	if (syscall(__NR_getrandom, out, len, 0) == (ssize_t)len)
		return true;
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return false;
	for (errno = 0, i = 0; i < len; i += ret, ret = 0) {
		ret = read(fd, out + i, len - i);
		if (ret <= 0) {
			ret = errno ? -errno : -EIO;
			break;
		}
	}
	close(fd);
	errno = -ret;
	return i == len;
}
#else
#include <ntsecapi.h>
static inline bool __attribute__((__warn_unused_result__)) get_random_bytes(uint8_t *out, size_t len)
{
        return RtlGenRandom(out, len);
}
#endif

int genkey_main(int argc, const char *argv[])
{
	//puts("Not implemented for PQWG");
	uint8_t ipkey[WG_INITIATOR_PUBLIC_KEY_LEN], isk[WG_INITIATOR_PRIVATE_KEY_LEN];
	uint8_t rpkey[WG_RESPONDER_PUBLIC_KEY_LEN], rsk[WG_RESPONDER_PRIVATE_KEY_LEN];
	char base64[WG_KEY_LEN_HEX_MAX];

	if (argc != 1) {
        fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
        return 1;
	}

    rkem_static_keygen(ipkey, isk);
    kem_keygen(rpkey, rsk);

    key_to_base64_initiator_private(base64, isk);
    puts("# Initiator private");
    printf("InitiatorPrivateKey = %s\n", base64);

    // FILE *fp = fopen("initiator.key", "w");
    // fwrite(isk, 1, WG_INITIATOR_PRIVATE_KEY_LEN, fp);
    // fclose(fp);

    puts("# Initiator public");
    key_to_base64_initiator_public(base64, ipkey);
    printf("InitiatorPublicKey = %s\n", base64);

    // fp = fopen("initiator.pub", "w");
    // fwrite(ipkey, 1, WG_INITIATOR_PUBLIC_KEY_LEN, fp);
    // fclose(fp);

    puts("");
    puts("# Responder private");
    key_to_base64_responder_private(base64, rsk);
    printf("ResponderPrivateKey = %s\n", base64);

    // fp = fopen("responder.key", "w");
    // fwrite(rsk, 1, WG_RESPONDER_PRIVATE_KEY_LEN, fp);
    // fclose(fp);

    puts("# Responder public");
    key_to_base64_responder_public(base64, rpkey);
    printf("ResponderPublicKey = %s\n", base64);

    // fp = fopen("responder.pub", "w");
    // fwrite(rpkey, 1, WG_RESPONDER_PUBLIC_KEY_LEN, fp);
    // fclose(fp);


	return 0;
}
