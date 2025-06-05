// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "containers.h"
#include "config.h"
#include "ipc.h"
#include "subcommands.h"

struct pubkey_origin {
	uint8_t *initiator_pubkey;
	uint8_t *responder_pubkey;
	bool has_initiator;
	bool has_responder;
	bool from_file;
};

static int pubkey_cmp(const void *first, const void *second)
{
	const struct pubkey_origin *a = first, *b = second;
	int ret = 0;
	if (a->has_initiator && b->has_initiator)
		ret |= memcmp(a->initiator_pubkey, b->initiator_pubkey, WG_INITIATOR_PUBLIC_KEY_LEN);
	if (a->has_responder && b->has_responder)
		ret |= memcmp(a->responder_pubkey, b->responder_pubkey, WG_RESPONDER_PUBLIC_KEY_LEN);
	if (ret)
		return ret;
	return (a->from_file - b->from_file) | (a->has_initiator - b->has_initiator) | (a->has_responder - b->has_responder);
}

static bool sync_conf(struct wgdevice *file)
{
	struct wgdevice *runtime;
	struct wgpeer *peer;
	struct pubkey_origin *pubkeys;
	size_t peer_count = 0, i = 0;

	if (!file->first_peer)
		return true;

	for_each_wgpeer(file, peer)
		++peer_count;

	if (ipc_get_device(&runtime, file->name) != 0) {
		perror("Unable to retrieve current interface configuration");
		return false;
	}

	if (!runtime->first_peer) {
		free_wgdevice(runtime);
		return true;
	}

	file->flags &= ~WGDEVICE_REPLACE_PEERS;

	for_each_wgpeer(runtime, peer)
		++peer_count;

	pubkeys = calloc(peer_count, sizeof(*pubkeys));
	if (!pubkeys) {
		free_wgdevice(runtime);
		perror("Public key allocation");
		return false;
	}

	for_each_wgpeer(file, peer) {
		if (peer->flags & WGPEER_HAS_INITIATOR_PUBLIC_KEY) {
			pubkeys[i].has_initiator = true;
			pubkeys[i].initiator_pubkey = peer->initiator_public_key;
		}
		if (peer->flags & WGPEER_HAS_RESPONDER_PUBLIC_KEY) {
			pubkeys[i].has_responder = true;
			pubkeys[i].responder_pubkey = peer->responder_public_key;
		}
		pubkeys[i].from_file = true;
		++i;
	}
	for_each_wgpeer(runtime, peer) {
		if (peer->flags & WGPEER_HAS_INITIATOR_PUBLIC_KEY) {
			pubkeys[i].has_initiator = true;
			pubkeys[i].initiator_pubkey = peer->initiator_public_key;
		}
		if (peer->flags & WGPEER_HAS_RESPONDER_PUBLIC_KEY) {
			pubkeys[i].has_responder = true;
			pubkeys[i].responder_pubkey = peer->responder_public_key;
		}
		pubkeys[i].from_file = false;
		++i;
	}
	qsort(pubkeys, peer_count, sizeof(*pubkeys), pubkey_cmp);

	for (i = 0; i < peer_count; ++i) {
		if (pubkeys[i].from_file)
			continue;
		bool initiator_keys_same = false;
		bool responder_keys_same = false;
		if (i < peer_count - 1){
			// keys are the same if they:
			initiator_keys_same = (
				// both have the same has_initiator
				pubkeys[i].has_initiator == pubkeys[i+i].has_initiator
				// AND
				&& (
					// has_initiator is FALSE
					!pubkeys[i].has_initiator
					// OR the keys are equal
					|| !memcmp(pubkeys[i].initiator_pubkey, pubkeys[i+i].initiator_pubkey, WG_INITIATOR_PUBLIC_KEY_LEN)
				)
			);
			responder_keys_same = pubkeys[i].has_responder == pubkeys[i+i].has_responder && (!pubkeys[i].has_responder || !memcmp(pubkeys[i].responder_pubkey, pubkeys[i+i].responder_pubkey, WG_RESPONDER_PUBLIC_KEY_LEN));
		}
		if (i == peer_count - 1 || !pubkeys[i + 1].from_file || !initiator_keys_same || !responder_keys_same) {
			peer = calloc(1, sizeof(struct wgpeer));
			if (!peer) {
				free_wgdevice(runtime);
				free(pubkeys);
				perror("Peer allocation");
				return false;
			}
			peer->flags = WGPEER_REMOVE_ME;
			if (pubkeys[i].has_initiator) {
				peer->flags |= WGPEER_HAS_INITIATOR_PUBLIC_KEY;
				memcpy(peer->initiator_public_key, pubkeys[i].initiator_pubkey, WG_INITIATOR_PUBLIC_KEY_LEN);
			}
			if (pubkeys[i].has_responder) {
				peer->flags |= WGPEER_HAS_RESPONDER_PUBLIC_KEY;
				memcpy(peer->responder_public_key, pubkeys[i].responder_pubkey, WG_RESPONDER_PUBLIC_KEY_LEN);
			}
			peer->next_peer = file->first_peer;
			file->first_peer = peer;
			if (!file->last_peer)
				file->last_peer = peer;
		}
	}
	free_wgdevice(runtime);
	free(pubkeys);
	return true;
}

int setconf_main(int argc, const char *argv[])
{
	struct wgdevice *device = NULL;
	struct config_ctx ctx;
	FILE *config_input = NULL;
	char *config_buffer = NULL;
	size_t config_buffer_len = 0;
	int ret = 1;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s %s <interface> <configuration filename>\n", PROG_NAME, argv[0]);
		return 1;
	}

	config_input = fopen(argv[2], "r");
	if (!config_input) {
		perror("fopen");
		return 1;
	}
	if (!config_read_init(&ctx, !strcmp(argv[0], "addconf"))) {
		fclose(config_input);
		return 1;
	}
	while (getline(&config_buffer, &config_buffer_len, config_input) >= 0) {
		if (!config_read_line(&ctx, config_buffer)) {
			fprintf(stderr, "Configuration parsing error\n");
			goto cleanup;
		}
	}
	device = config_read_finish(&ctx);
	if (!device) {
		fprintf(stderr, "Invalid configuration\n");
		goto cleanup;
	}
	strncpy(device->name, argv[1], IFNAMSIZ - 1);
	device->name[IFNAMSIZ - 1] = '\0';

	if (!strcmp(argv[0], "syncconf")) {
		if (!sync_conf(device))
			goto cleanup;
	}

	if (ipc_set_device(device) != 0) {
		perror("Unable to modify interface");
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (config_input)
		fclose(config_input);
	free(config_buffer);
	free_wgdevice(device);
	return ret;
}
