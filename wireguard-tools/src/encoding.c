// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is a specialized constant-time base64/hex implementation that resists side-channel attacks.
 */

#include <string.h>
#include "encoding.h"
#include "uapi/linux/linux/wireguard.h"

// SPDX-License-Identifier: GPL-2.0
/*
 * base64.c - RFC4648-compliant base64 encoding
 *
 * Copyright (c) 2020 Hannes Reinecke, SUSE
 *
 * Based on the base64url routines from fs/crypto/fname.c
 * (which are using the URL-safe base64 encoding),
 * modified to use the standard coding table from RFC4648 section 4.
 */

#include <stdint.h>


static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode() - base64-encode some binary data
 * @src: the binary data to encode
 * @srclen: the length of @src in bytes
 * @dst: (output) the base64-encoded string.  Not NUL-terminated.
 *
 * Encodes data using base64 encoding, i.e. the "Base 64 Encoding" specified
 * by RFC 4648, including the  '='-padding.
 *
 * Return: the length of the resulting base64-encoded string in bytes.
 */
static int base64_encode(const u8 *src, int srclen, char *dst)
{
	uint32_t ac = 0;
	int bits = 0;
	int i;
	char *cp = dst;

	for (i = 0; i < srclen; i++) {
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64_table[(ac >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits) {
		*cp++ = base64_table[(ac << (6 - bits)) & 0x3f];
		bits -= 6;
	}
	while (bits < 0) {
		*cp++ = '=';
		bits += 2;
	}
	return cp - dst;
}

/**
 * base64_decode() - base64-decode a string
 * @src: the string to decode.  Doesn't need to be NUL-terminated.
 * @srclen: the length of @src in bytes
 * @dst: (output) the decoded binary data
 *
 * Decodes a string using base64 encoding, i.e. the "Base 64 Encoding"
 * specified by RFC 4648, including the  '='-padding.
 *
 * This implementation hasn't been optimized for performance.
 *
 * Return: the length of the resulting decoded binary data in bytes,
 *	   or -1 if the string isn't a valid base64 string.
*/
static int base64_decode(const char *src, int srclen, u8 *dst)
{
	uint32_t ac = 0;
	int bits = 0;
	int i;
	uint8_t *bp = dst;

	for (i = 0; i < srclen; i++) {
		const char *p = strchr(base64_table, src[i]);

		if (src[i] == '=') {
			ac = (ac << 6);
			bits += 6;
			if (bits >= 8)
				bits -= 8;
			continue;
		}
		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (u8)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

#define ENCODING_FUNCTION(name) name ## _initiator_private
#define WG_KEY_LEN WG_INITIATOR_PRIVATE_KEY_LEN
#include "encoding_functions.inc"

#define ENCODING_FUNCTION(name) name ## _initiator_public
#define WG_KEY_LEN WG_INITIATOR_PUBLIC_KEY_LEN
#include "encoding_functions.inc"

#define ENCODING_FUNCTION(name) name ## _responder_private
#define WG_KEY_LEN WG_RESPONDER_PRIVATE_KEY_LEN
#include "encoding_functions.inc"

#define ENCODING_FUNCTION(name) name ## _responder_public
#define WG_KEY_LEN WG_RESPONDER_PUBLIC_KEY_LEN
#include "encoding_functions.inc"

#define ENCODING_FUNCTION(name) name ## _psk
#define WG_KEY_LEN WG_PSK_KEY_LEN
#include "encoding_functions.inc"
