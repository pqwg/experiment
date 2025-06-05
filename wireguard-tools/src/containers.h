/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef CONTAINERS_H
#define CONTAINERS_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include "uapi/linux/linux/wireguard.h"

#include "rkem/rkem.h"
#include "kem/kem.h"

/* Cross platform __kernel_timespec */
struct timespec64 {
	int64_t tv_sec;
	int64_t tv_nsec;
};

struct wgallowedip {
	uint16_t family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	};
	uint8_t cidr;
	struct wgallowedip *next_allowedip;
};

enum {
	WGPEER_REMOVE_ME = 1U << 0,
	WGPEER_REPLACE_ALLOWEDIPS = 1U << 1,
	WGPEER_HAS_INITIATOR_PUBLIC_KEY = 1U << 2,
	WGPEER_HAS_PRESHARED_KEY = 1U << 3,
	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4,
	WGPEER_HAS_RESPONDER_PUBLIC_KEY = 1U << 5,
};

struct wgpeer {
	uint32_t flags;

	uint8_t initiator_public_key[RKEM_STATIC_PUBLIC_KEY_BYTES];
	uint8_t responder_public_key[KEM_PUBLIC_KEY_SIZE];
	uint8_t preshared_key[WG_PSK_KEY_LEN];

	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} endpoint;

	struct timespec64 last_handshake_time;
	uint64_t rx_bytes, tx_bytes;
	uint16_t persistent_keepalive_interval;

	struct wgallowedip *first_allowedip, *last_allowedip;
	struct wgpeer *next_peer;
};

enum {
	WGDEVICE_REPLACE_PEERS = 1U << 0,
	WGDEVICE_HAS_INITIATOR_PRIVATE_KEY = 1U << 1,
	WGDEVICE_HAS_INITIATOR_PUBLIC_KEY = 1U << 2,
	WGDEVICE_HAS_LISTEN_PORT = 1U << 3,
	WGDEVICE_HAS_FWMARK = 1U << 4,
	WGDEVICE_HAS_RESPONDER_PRIVATE_KEY = 1U << 5,
	WGDEVICE_HAS_RESPONDER_PUBLIC_KEY = 1U << 6,
};

struct wgdevice {
	char name[IF_NAMESIZE];
	uint32_t ifindex;

	uint32_t flags;

	uint8_t initiator_public_key[RKEM_STATIC_PUBLIC_KEY_BYTES];
	uint8_t initiator_private_key[RKEM_STATIC_PRIVATE_KEY_BYTES];

	uint8_t responder_public_key[KEM_PUBLIC_KEY_SIZE];
	uint8_t responder_private_key[KEM_PRIVATE_KEY_SIZE];

	uint32_t fwmark;
	uint16_t listen_port;

	struct wgpeer *first_peer, *last_peer;
};

#define for_each_wgpeer(__dev, __peer) for ((__peer) = (__dev)->first_peer; (__peer); (__peer) = (__peer)->next_peer)
#define for_each_wgallowedip(__peer, __allowedip) for ((__allowedip) = (__peer)->first_allowedip; (__allowedip); (__allowedip) = (__allowedip)->next_allowedip)

static inline void free_wgdevice(struct wgdevice *dev)
{
	if (!dev)
		return;
	for (struct wgpeer *peer = dev->first_peer, *np = peer ? peer->next_peer : NULL; peer; peer = np, np = peer ? peer->next_peer : NULL) {
		for (struct wgallowedip *allowedip = peer->first_allowedip, *na = allowedip ? allowedip->next_allowedip : NULL; allowedip; allowedip = na, na = allowedip ? allowedip->next_allowedip : NULL)
			free(allowedip);
		free(peer);
	}
	free(dev);
}

#endif
