// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#include "containers.h"
#include "encoding.h"
#include "ipc.h"
#include "subcommands.h"

int showconf_main(int argc, const char *argv[])
{
#define MAX(a,b) (((a)>(b))?(a):(b))
	#define WG_KEY_LEN MAX(WG_INITIATOR_PRIVATE_KEY_LEN, MAX(WG_RESPONDER_PRIVATE_KEY_LEN, MAX(WG_INITIATOR_PUBLIC_KEY_LEN, WG_RESPONDER_PUBLIC_KEY_LEN)))
        #define WG_KEY_LEN_HEX (WG_KEY_LEN * 2 + 1)
	char base64[WG_KEY_LEN_HEX];
	char ip[INET6_ADDRSTRLEN];
	struct wgdevice *device = NULL;
	struct wgpeer *peer;
	struct wgallowedip *allowedip;
	int ret = 1;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s %s <interface>\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (ipc_get_device(&device, argv[1])) {
		perror("Unable to access interface");
		goto cleanup;
	}

	printf("[Interface]\n");
	if (device->listen_port)
		printf("ListenPort = %u\n", device->listen_port);
	if (device->fwmark)
		printf("FwMark = 0x%x\n", device->fwmark);
	if (device->flags & WGDEVICE_HAS_INITIATOR_PRIVATE_KEY) {
		key_to_base64_initiator_private(base64, device->initiator_private_key);
		printf("InitiatorPrivateKey = %s\n", base64);
		key_to_base64_initiator_public(base64, device->initiator_public_key);
		printf("InitiatorPublicKey = %s\n", base64);
	}
	if (device->flags & WGDEVICE_HAS_RESPONDER_PRIVATE_KEY) {
		key_to_base64_responder_private(base64, device->responder_private_key);
		printf("ResponderPrivateKey = %s\n", base64);
		key_to_base64_responder_public(base64, device->responder_public_key);
		printf("ResponderPublicKey = %s\n", base64);
	}
	printf("\n");
	for_each_wgpeer(device, peer) {
		printf("[Peer]\n");
		if (peer->flags & WGPEER_HAS_INITIATOR_PUBLIC_KEY) {
			key_to_base64_initiator_public(base64, peer->initiator_public_key);
			printf("InitiatorPublicKey = %s\n", base64);
		}
		if (peer->flags & WGPEER_HAS_RESPONDER_PUBLIC_KEY) {
			key_to_base64_responder_public(base64, peer->responder_public_key);
			printf("ResponderPublicKey = %s\n", base64);
		}
		if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
			key_to_base64_psk(base64, peer->preshared_key);
			printf("PresharedKey = %s\n", base64);
		}
		if (peer->first_allowedip)
			printf("AllowedIPs = ");
		for_each_wgallowedip(peer, allowedip) {
			if (allowedip->family == AF_INET) {
				if (!inet_ntop(AF_INET, &allowedip->ip4, ip, INET6_ADDRSTRLEN))
					continue;
			} else if (allowedip->family == AF_INET6) {
				if (!inet_ntop(AF_INET6, &allowedip->ip6, ip, INET6_ADDRSTRLEN))
					continue;
			} else
				continue;
			printf("%s/%d", ip, allowedip->cidr);
			if (allowedip->next_allowedip)
				printf(", ");
		}
		if (peer->first_allowedip)
			printf("\n");

		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6) {
			char host[4096 + 1];
			char service[512 + 1];
			socklen_t addr_len = 0;

			if (peer->endpoint.addr.sa_family == AF_INET)
				addr_len = sizeof(struct sockaddr_in);
			else if (peer->endpoint.addr.sa_family == AF_INET6)
				addr_len = sizeof(struct sockaddr_in6);
			if (!getnameinfo(&peer->endpoint.addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST)) {
				if (peer->endpoint.addr.sa_family == AF_INET6 && strchr(host, ':'))
					printf("Endpoint = [%s]:%s\n", host, service);
				else
					printf("Endpoint = %s:%s\n", host, service);
			}
		}

		if (peer->persistent_keepalive_interval)
			printf("PersistentKeepalive = %u\n", peer->persistent_keepalive_interval);

		if (peer->next_peer)
			printf("\n");
	}
	ret = 0;

cleanup:
	free_wgdevice(device);
	return ret;
}
