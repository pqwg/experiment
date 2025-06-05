/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#ifndef _WG_NOISE_H
#define _WG_NOISE_H

#include "messages.h"
#include "peerlookup.h"

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/kref.h>

struct noise_replay_counter {
	u64 counter;
	spinlock_t lock;
	unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG];
};

struct noise_symmetric_key {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u64 birthdate;
	bool is_valid;
};

struct noise_keypair {
	struct index_hashtable_entry entry;
	struct noise_symmetric_key sending;
	atomic64_t sending_counter;
	struct noise_symmetric_key receiving;
	struct noise_replay_counter receiving_counter;
	__le32 remote_index;
	bool i_am_the_initiator;
	struct kref refcount;
	struct rcu_head rcu;
	u64 internal_id;
};

struct noise_keypairs {
	struct noise_keypair __rcu *current_keypair;
	struct noise_keypair __rcu *previous_keypair;
	struct noise_keypair __rcu *next_keypair;
	spinlock_t keypair_update_lock;
};

struct noise_static_identity {
	u8 responder_public[NOISE_RESPONDER_PUBLIC_KEY_LEN];
	u8 responder_private[NOISE_RESPONDER_PRIVATE_KEY_LEN];
	u8 initiator_public_hash[NOISE_PK_HASH_LEN];
	u8 initiator_public[NOISE_INITIATOR_PUBLIC_KEY_LEN];
	u8 initiator_private[NOISE_INITIATOR_PRIVATE_KEY_LEN];
	struct rw_semaphore lock;
	bool has_initiator_identity;
	bool has_responder_identity;
};

enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE
};

struct noise_handshake {
	struct index_hashtable_entry entry;

	enum noise_handshake_state state;
	u64 last_initiation_consumption;

	struct noise_static_identity *static_identity;

	u8 ephemeral_private[NOISE_EPHEMERAL_PRIVATE_KEY_LEN];
	u8 ephemeral_public[NOISE_EPHEMERAL_PUBLIC_KEY_LEN];
	u8 remote_static_public_responder[NOISE_RESPONDER_PUBLIC_KEY_LEN];
	u8 remote_static_public_initiator[NOISE_INITIATOR_PUBLIC_KEY_LEN];
	u8 remote_static_initiator_hash[NOISE_PK_HASH_LEN];
	u8 remote_ciphertext[NOISE_RESPONSE_CIPHERTEXT_LEN];
	//u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];

	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
        u8 key[NOISE_HASH_LEN];

	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];

	u64 bench_timer;
	__le32 remote_index;

	struct kem_buffer kem_buf;
	struct rkem_buffer rkem_buf;

	bool has_initiator_public;
	bool has_responder_public;

	/* Protects all members except the immutable (after noise_handshake_
	 * init): remote_static, precomputed_static_static, static_identity.
	 */
	struct rw_semaphore lock;
};

struct wg_device;

void wg_noise_init(void);
void wg_noise_handshake_init(struct noise_handshake *handshake,
			     struct noise_static_identity *static_identity,
			     const u8 peer_public_key_r[NOISE_RESPONDER_PUBLIC_KEY_LEN],
			     const u8 peer_public_key_i[NOISE_INITIATOR_PUBLIC_KEY_LEN],
			     const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
			     struct wg_peer *peer);
void wg_noise_handshake_clear(struct noise_handshake *handshake);
static inline void wg_noise_reset_last_sent_handshake(atomic64_t *handshake_ns)
{
	atomic64_set(handshake_ns, ktime_get_coarse_boottime_ns() -
				       (u64)(REKEY_TIMEOUT + 1) * NSEC_PER_SEC);
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now);
struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair);
void wg_noise_keypairs_clear(struct noise_keypairs *keypairs);
bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
				    struct noise_keypair *received_keypair);
void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer);

/* Must hold static_identity->lock */
void wg_noise_set_static_identity_private_key(
	struct noise_static_identity *static_identity,
	const u8 responder_public[NOISE_RESPONDER_PUBLIC_KEY_LEN],
	const u8 responder_private[NOISE_RESPONDER_PRIVATE_KEY_LEN],
	const u8 initiator_public[NOISE_INITIATOR_PUBLIC_KEY_LEN],
	const u8 initiator_private[NOISE_INITIATOR_PRIVATE_KEY_LEN],
	const u8 initiator_public_hash[NOISE_PK_HASH_LEN]
);

void wg_noise_precompute_static_static(struct wg_peer *peer);

bool
wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst,
				     struct noise_handshake *handshake);
struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
				      struct wg_device *wg);

bool wg_noise_handshake_create_response(struct message_handshake_response *dst,
					struct noise_handshake *handshake);
struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
				    struct wg_device *wg);

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
				      struct noise_keypairs *keypairs);

static inline
void digest_pk(u8 hash[NOISE_PK_HASH_LEN], const u8 pk[NOISE_INITIATOR_PUBLIC_KEY_LEN]) {
	static u8 key[10] = "WIREGUARD";
	blake2s(hash, pk, key, NOISE_PK_HASH_LEN, NOISE_INITIATOR_PUBLIC_KEY_LEN, sizeof(key));
}

static inline
void digest_pk_responder(u8 hash[NOISE_PK_HASH_LEN], const u8 pk[NOISE_RESPONDER_PUBLIC_KEY_LEN]) {
	static u8 key[10] = "WIREGUARD";
	blake2s(hash, pk, key, NOISE_PK_HASH_LEN, NOISE_RESPONDER_PUBLIC_KEY_LEN, sizeof(key));
}

#endif /* _WG_NOISE_H */
