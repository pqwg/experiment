// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "noise.h"
#include "device.h"
#include "peer.h"
#include "messages.h"
#include "queueing.h"
#include "peerlookup.h"

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <crypto/utils.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static const u8 handshake_name[47] = "Noise_IKpsk1rkem_25519_ChaChaPoly_BLAKE2s_RKEM";
static const u8 identifier_name[37] = "PQWireGuard v2 zx2c4 Jason@zx2c4.com";
static u8 handshake_init_hash[NOISE_HASH_LEN] __ro_after_init;
static u8 handshake_init_chaining_key[NOISE_HASH_LEN] __ro_after_init;
static atomic64_t keypair_counter = ATOMIC64_INIT(0);

#ifndef DEBUG
#define DEBUG_PRINT_KEY(label, buf, len)
#else
#define DEBUG_PRINT_KEY(label, buf, len) print_hex_dump_bytes(label " ", DUMP_PREFIX_NONE, buf, len)
#endif


void __init wg_noise_init(void)
{
	struct blake2s_state blake;

	blake2s(handshake_init_chaining_key, handshake_name, NULL,
		NOISE_HASH_LEN, sizeof(handshake_name), 0);
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash);
}

///* Must hold peer->handshake.static_identity->lock */
//void wg_noise_precompute_static_static(struct wg_peer *peer)
//{
//	down_write(&peer->handshake.lock);
//	if (!peer->handshake.static_identity->has_identity ||
//	    !curve25519(peer->handshake.precomputed_static_static,
//			peer->handshake.static_identity->static_private,
//			peer->handshake.remote_static))
//		memset(peer->handshake.precomputed_static_static, 0,
//		       NOISE_PUBLIC_KEY_LEN);
//	up_write(&peer->handshake.lock);
//}

void wg_noise_handshake_init(struct noise_handshake *handshake,
			     struct noise_static_identity *static_identity,
			     const u8 peer_public_key_r[NOISE_RESPONDER_PUBLIC_KEY_LEN],
			     const u8 peer_public_key_i[NOISE_INITIATOR_PUBLIC_KEY_LEN],
			     const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
			     struct wg_peer *peer)
{
	memset(handshake, 0, sizeof(*handshake));
	init_rwsem(&handshake->lock);
	handshake->entry.type = INDEX_HASHTABLE_HANDSHAKE;
	handshake->entry.peer = peer;
	if (peer_public_key_r) {
		pr_debug("Has responder public");
		memcpy(handshake->remote_static_public_responder, peer_public_key_r, NOISE_RESPONDER_PUBLIC_KEY_LEN);
		// just hash the remote static key as id anyway to be able to find it anyway
		digest_pk_responder(handshake->remote_static_initiator_hash, peer_public_key_r);
		handshake->has_responder_public = true;
	}
	if (peer_public_key_i) {
		pr_debug("has initiator public");
        DEBUG_PRINT_KEY("peer ipub",peer_public_key_i, 16);
		memcpy(handshake->remote_static_public_initiator, peer_public_key_i, NOISE_INITIATOR_PUBLIC_KEY_LEN);
		digest_pk(handshake->remote_static_initiator_hash, peer_public_key_i);
		handshake->has_initiator_public = true;
	}
	if (peer_preshared_key)
		memcpy(handshake->preshared_key, peer_preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
	handshake->static_identity = static_identity;
	handshake->state = HANDSHAKE_ZEROED;

	kem_init(&handshake->kem_buf);
	rkem_init(&handshake->rkem_buf);

	// wg_noise_precompute_static_static(peer);
}

static void handshake_zero(struct noise_handshake *handshake)
{
	memset(&handshake->ephemeral_private, 0, NOISE_EPHEMERAL_PRIVATE_KEY_LEN);
	memset(&handshake->remote_ciphertext, 0, NOISE_RESPONSE_CIPHERTEXT_LEN);
	memset(&handshake->hash, 0, NOISE_HASH_LEN);
	memset(&handshake->chaining_key, 0, NOISE_HASH_LEN);
	handshake->remote_index = 0;
	kem_clear(&handshake->kem_buf);
	rkem_clear(&handshake->rkem_buf);
	handshake->state = HANDSHAKE_ZEROED;
}

void wg_noise_handshake_clear(struct noise_handshake *handshake)
{
	down_write(&handshake->lock);
	wg_index_hashtable_remove(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry);
	handshake_zero(handshake);
	up_write(&handshake->lock);
}

static struct noise_keypair *keypair_create(struct wg_peer *peer)
{
	struct noise_keypair *keypair = kzalloc(sizeof(*keypair), GFP_KERNEL);

	if (unlikely(!keypair))
		return NULL;
	spin_lock_init(&keypair->receiving_counter.lock);
	keypair->internal_id = atomic64_inc_return(&keypair_counter);
	keypair->entry.type = INDEX_HASHTABLE_KEYPAIR;
	keypair->entry.peer = peer;
	kref_init(&keypair->refcount);
	return keypair;
}

static void keypair_free_rcu(struct rcu_head *rcu)
{
	kfree_sensitive(container_of(rcu, struct noise_keypair, rcu));
}

static void keypair_free_kref(struct kref *kref)
{
	struct noise_keypair *keypair =
		container_of(kref, struct noise_keypair, refcount);

	net_dbg_ratelimited("%s: Keypair %llu destroyed for peer %llu\n",
			    keypair->entry.peer->device->dev->name,
			    keypair->internal_id,
			    keypair->entry.peer->internal_id);
	wg_index_hashtable_remove(keypair->entry.peer->device->index_hashtable,
				  &keypair->entry);
	call_rcu(&keypair->rcu, keypair_free_rcu);
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now)
{
	if (unlikely(!keypair))
		return;
	if (unlikely(unreference_now))
		wg_index_hashtable_remove(
			keypair->entry.peer->device->index_hashtable,
			&keypair->entry);
	kref_put(&keypair->refcount, keypair_free_kref);
}

struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
		"Taking noise keypair reference without holding the RCU BH read lock");
	if (unlikely(!keypair || !kref_get_unless_zero(&keypair->refcount)))
		return NULL;
	return keypair;
}

void wg_noise_keypairs_clear(struct noise_keypairs *keypairs)
{
	struct noise_keypair *old;

	spin_lock_bh(&keypairs->keypair_update_lock);

	/* We zero the next_keypair before zeroing the others, so that
	 * wg_noise_received_with_keypair returns early before subsequent ones
	 * are zeroed.
	 */
	old = rcu_dereference_protected(keypairs->next_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);
	wg_noise_keypair_put(old, true);

	old = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
	wg_noise_keypair_put(old, true);

	old = rcu_dereference_protected(keypairs->current_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->current_keypair, NULL);
	wg_noise_keypair_put(old, true);

	spin_unlock_bh(&keypairs->keypair_update_lock);
}

void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer)
{
	struct noise_keypair *keypair;

	wg_noise_handshake_clear(&peer->handshake);
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);

	spin_lock_bh(&peer->keypairs.keypair_update_lock);
	keypair = rcu_dereference_protected(peer->keypairs.next_keypair,
			lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	keypair = rcu_dereference_protected(peer->keypairs.current_keypair,
			lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	spin_unlock_bh(&peer->keypairs.keypair_update_lock);
}

static void add_new_keypair(struct noise_keypairs *keypairs,
			    struct noise_keypair *new_keypair)
{
	struct noise_keypair *previous_keypair, *next_keypair, *current_keypair;

	spin_lock_bh(&keypairs->keypair_update_lock);
	previous_keypair = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	next_keypair = rcu_dereference_protected(keypairs->next_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	current_keypair = rcu_dereference_protected(keypairs->current_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	if (new_keypair->i_am_the_initiator) {
		/* If we're the initiator, it means we've sent a handshake, and
		 * received a confirmation response, which means this new
		 * keypair can now be used.
		 */
		if (next_keypair) {
			/* If there already was a next keypair pending, we
			 * demote it to be the previous keypair, and free the
			 * existing current. Note that this means KCI can result
			 * in this transition. It would perhaps be more sound to
			 * always just get rid of the unused next keypair
			 * instead of putting it in the previous slot, but this
			 * might be a bit less robust. Something to think about
			 * for the future.
			 */
			RCU_INIT_POINTER(keypairs->next_keypair, NULL);
			rcu_assign_pointer(keypairs->previous_keypair,
					   next_keypair);
			wg_noise_keypair_put(current_keypair, true);
		} else /* If there wasn't an existing next keypair, we replace
			* the previous with the current one.
			*/
			rcu_assign_pointer(keypairs->previous_keypair,
					   current_keypair);
		/* At this point we can get rid of the old previous keypair, and
		 * set up the new keypair.
		 */
		wg_noise_keypair_put(previous_keypair, true);
		rcu_assign_pointer(keypairs->current_keypair, new_keypair);
	} else {
		/* If we're the responder, it means we can't use the new keypair
		 * until we receive confirmation via the first data packet, so
		 * we get rid of the existing previous one, the possibly
		 * existing next one, and slide in the new next one.
		 */
		rcu_assign_pointer(keypairs->next_keypair, new_keypair);
		wg_noise_keypair_put(next_keypair, true);
		RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
		wg_noise_keypair_put(previous_keypair, true);
	}
	spin_unlock_bh(&keypairs->keypair_update_lock);
}

bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
				    struct noise_keypair *received_keypair)
{
	struct noise_keypair *old_keypair;
	bool key_is_new;

	/* We first check without taking the spinlock. */
	key_is_new = received_keypair ==
		     rcu_access_pointer(keypairs->next_keypair);
	if (likely(!key_is_new))
		return false;

	spin_lock_bh(&keypairs->keypair_update_lock);
	/* After locking, we double check that things didn't change from
	 * beneath us.
	 */
	if (unlikely(received_keypair !=
		    rcu_dereference_protected(keypairs->next_keypair,
			    lockdep_is_held(&keypairs->keypair_update_lock)))) {
		spin_unlock_bh(&keypairs->keypair_update_lock);
		return false;
	}

	/* When we've finally received the confirmation, we slide the next
	 * into the current, the current into the previous, and get rid of
	 * the old previous.
	 */
	old_keypair = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	rcu_assign_pointer(keypairs->previous_keypair,
		rcu_dereference_protected(keypairs->current_keypair,
			lockdep_is_held(&keypairs->keypair_update_lock)));
	wg_noise_keypair_put(old_keypair, true);
	rcu_assign_pointer(keypairs->current_keypair, received_keypair);
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);

	spin_unlock_bh(&keypairs->keypair_update_lock);
	return true;
}

/* Must hold static_identity->lock */
void wg_noise_set_static_identity_private_key(
	struct noise_static_identity *static_identity,
	const u8 responder_public[NOISE_RESPONDER_PUBLIC_KEY_LEN],
	const u8 responder_private[NOISE_RESPONDER_PRIVATE_KEY_LEN],
	const u8 initiator_public[NOISE_INITIATOR_PUBLIC_KEY_LEN],
	const u8 initiator_private[NOISE_INITIATOR_PRIVATE_KEY_LEN],
	const u8 public_hash[NOISE_PK_HASH_LEN]
) {
	static_identity->has_initiator_identity = initiator_private && initiator_public;
	static_identity->has_responder_identity = responder_private && responder_public;
    if (!static_identity->has_initiator_identity && !static_identity->has_responder_identity) {
        pr_err("WTF");
    }
	if (responder_private && responder_public) {
		memcpy(static_identity->responder_public, responder_public, NOISE_RESPONDER_PUBLIC_KEY_LEN);
		memcpy(static_identity->responder_private, responder_private, NOISE_RESPONDER_PRIVATE_KEY_LEN);
	}
	if (initiator_private && initiator_public) {
		memcpy(static_identity->initiator_public, initiator_public, NOISE_INITIATOR_PUBLIC_KEY_LEN);
		memcpy(static_identity->initiator_private, initiator_private, NOISE_INITIATOR_PRIVATE_KEY_LEN);
	}
	memcpy(static_identity->initiator_public_hash, public_hash, NOISE_PK_HASH_LEN);
}

//void wg_noise_set_static_identity_private_key(
//	struct noise_static_identity *static_identity,
//	const u8 private_key[NOISE_PUBLIC_KEY_LEN])
//{
//	memcpy(static_identity->static_private, private_key,
//	       NOISE_PUBLIC_KEY_LEN);
//	curve25519_clamp_secret(static_identity->static_private);
//	static_identity->has_identity = curve25519_generate_public(
//		static_identity->static_public, private_key);
//}

static void hmac(u8 *out, const u8 *in, const u8 *key, const size_t inlen, const size_t keylen)
{
	struct blake2s_state state;
	u8 x_key[BLAKE2S_BLOCK_SIZE] __aligned(__alignof__(u32)) = { 0 };
	u8 i_hash[BLAKE2S_HASH_SIZE] __aligned(__alignof__(u32));
	int i;

	if (keylen > BLAKE2S_BLOCK_SIZE) {
		blake2s_init(&state, BLAKE2S_HASH_SIZE);
		blake2s_update(&state, key, keylen);
		blake2s_final(&state, x_key);
	} else
		memcpy(x_key, key, keylen);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x36;

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, in, inlen);
	blake2s_final(&state, i_hash);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x5c ^ 0x36;

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, i_hash, BLAKE2S_HASH_SIZE);
	blake2s_final(&state, i_hash);

	memcpy(out, i_hash, BLAKE2S_HASH_SIZE);
	memzero_explicit(x_key, BLAKE2S_BLOCK_SIZE);
	memzero_explicit(i_hash, BLAKE2S_HASH_SIZE);
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static void kdf(u8 *first_dst, u8 *second_dst, u8 *third_dst, const u8 *data,
		size_t first_len, size_t second_len, size_t third_len,
		size_t data_len, const u8 chaining_key[NOISE_HASH_LEN])
{
	u8 output[BLAKE2S_HASH_SIZE + 1];
	u8 secret[BLAKE2S_HASH_SIZE];

	WARN_ON(IS_ENABLED(DEBUG) &&
		(first_len > BLAKE2S_HASH_SIZE ||
		 second_len > BLAKE2S_HASH_SIZE ||
		 third_len > BLAKE2S_HASH_SIZE ||
		 ((second_len || second_dst || third_len || third_dst) &&
		  (!first_len || !first_dst)) ||
		 ((third_len || third_dst) && (!second_len || !second_dst))));

	/* Extract entropy from data into secret */
	hmac(secret, data, chaining_key, data_len, NOISE_HASH_LEN);

	if (!first_dst || !first_len)
		goto out;

	/* Expand first key: key = secret, data = 0x1 */
	output[0] = 1;
	hmac(output, output, secret, 1, BLAKE2S_HASH_SIZE);
	memcpy(first_dst, output, first_len);

	if (!second_dst || !second_len)
		goto out;

	/* Expand second key: key = secret, data = first-key || 0x2 */
	output[BLAKE2S_HASH_SIZE] = 2;
	hmac(output, output, secret, BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(second_dst, output, second_len);

	if (!third_dst || !third_len)
		goto out;

	/* Expand third key: key = secret, data = second-key || 0x3 */
	output[BLAKE2S_HASH_SIZE] = 3;
	hmac(output, output, secret, BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(third_dst, output, third_len);

out:
	/* Clear sensitive data from stack */
	memzero_explicit(secret, BLAKE2S_HASH_SIZE);
	memzero_explicit(output, BLAKE2S_HASH_SIZE + 1);
}

static void derive_keys(struct noise_symmetric_key *first_dst,
			struct noise_symmetric_key *second_dst,
			const u8 chaining_key[NOISE_HASH_LEN])
{
	u64 birthdate = ktime_get_coarse_boottime_ns();
	kdf(first_dst->key, second_dst->key, NULL, NULL,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
	    chaining_key);
	first_dst->birthdate = second_dst->birthdate = birthdate;
	first_dst->is_valid = second_dst->is_valid = true;
}

static void mix_kem_ss(u8 chaining_key[NOISE_HASH_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 shared_secret[RKEM_SHARED_SECRET_BYTES]) {
	kdf(chaining_key, key, NULL, shared_secret, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, RKEM_SHARED_SECRET_BYTES, chaining_key);
}

static void mix_key_chain_only(u8 chaining_key[NOISE_HASH_LEN], const u8 *shared_secret, size_t ss_len) {
    kdf(chaining_key, NULL, NULL, shared_secret, NOISE_HASH_LEN, 0, 0, ss_len, chaining_key);
}

// static bool __must_check mix_dh(u8 chaining_key[NOISE_HASH_LEN],
// 				u8 key[NOISE_SYMMETRIC_KEY_LEN],
// 				const u8 private[NOISE_PUBLIC_KEY_LEN],
// 				const u8 public[NOISE_PUBLIC_KEY_LEN])
// {
// 	u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];

// 	if (unlikely(!curve25519(dh_calculation, private, public)))
// 		return false;
// 	kdf(chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN,
// 	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
// 	memzero_explicit(dh_calculation, NOISE_PUBLIC_KEY_LEN);
// 	return true;
// }

// static bool __must_check mix_precomputed_dh(u8 chaining_key[NOISE_HASH_LEN],
// 					    u8 key[NOISE_SYMMETRIC_KEY_LEN],
// 					    const u8 precomputed[NOISE_PUBLIC_KEY_LEN])
// {
// 	static u8 zero_point[NOISE_PUBLIC_KEY_LEN];
// 	if (unlikely(!crypto_memneq(precomputed, zero_point, NOISE_PUBLIC_KEY_LEN)))
// 		return false;
// 	kdf(chaining_key, key, NULL, precomputed, NOISE_HASH_LEN,
// 	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN,
// 	    chaining_key);
// 	return true;
// }

static void mix_hash(u8 hash[NOISE_HASH_LEN], const u8 *src, size_t src_len)
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash);
}

static void mix_psk(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN],
		    u8 key[NOISE_SYMMETRIC_KEY_LEN],
		    const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	u8 temp_hash[NOISE_HASH_LEN];

	kdf(chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	mix_hash(hash, temp_hash, NOISE_HASH_LEN);
	memzero_explicit(temp_hash, NOISE_HASH_LEN);
}

static void handshake_init(u8 chaining_key[NOISE_HASH_LEN],
			   u8 hash[NOISE_HASH_LEN],
			   const u8 remote_static[NOISE_RESPONDER_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_RESPONDER_PUBLIC_KEY_LEN);
    mix_key_chain_only(chaining_key, remote_static, NOISE_RESPONDER_PUBLIC_KEY_LEN);
}

static void message_encrypt(u8 *dst_ciphertext, const u8 *src_plaintext,
			    size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
			    u8 hash[NOISE_HASH_LEN])
{
	chacha20poly1305_encrypt(dst_ciphertext, src_plaintext, src_len, hash,
				 NOISE_HASH_LEN,
				 0 /* Always zero for Noise_IK */, key);
	mix_hash(hash, dst_ciphertext, noise_encrypted_len(src_len));
}

static bool message_decrypt(u8 *dst_plaintext, const u8 *src_ciphertext,
			    size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
			    u8 hash[NOISE_HASH_LEN])
{
	if (!chacha20poly1305_decrypt(dst_plaintext, src_ciphertext, src_len,
				      hash, NOISE_HASH_LEN,
				      0 /* Always zero for Noise_IK */, key))
		return false;
	mix_hash(hash, src_ciphertext, src_len);
	return true;
}

// Hashes C3, H3
static void message_ephemeral(const u8 ephemeral_src[NOISE_EPHEMERAL_PUBLIC_KEY_LEN],
			      u8 chaining_key[NOISE_HASH_LEN],
			      u8 hash[NOISE_HASH_LEN])
{
	mix_hash(hash, ephemeral_src, NOISE_EPHEMERAL_PUBLIC_KEY_LEN);
	kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0,
	    NOISE_EPHEMERAL_PUBLIC_KEY_LEN, chaining_key);
}

static void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN])
{
	struct timespec64 now;

	ktime_get_real_ts64(&now);

	/* In order to prevent some sort of infoleak from precise timers, we
	 * round down the nanoseconds part to the closest rounded-down power of
	 * two to the maximum initiations per second allowed anyway by the
	 * implementation.
	 */
	now.tv_nsec = ALIGN_DOWN(now.tv_nsec,
		rounddown_pow_of_two(NSEC_PER_SEC / INITIATIONS_PER_SECOND));

	/* https://cr.yp.to/libtai/tai64.html */
	*(__be64 *)output = cpu_to_be64(0x400000000000000aULL + now.tv_sec);
	*(__be32 *)(output + sizeof(__be64)) = cpu_to_be32(now.tv_nsec);
}

bool
wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst,
				     struct noise_handshake *handshake)
{
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;
	u64 bench_timer = ktime_get_ns();

	//pr_debug("Client Creating initial msg");

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	wait_for_random_bytes();


	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

	handshake->bench_timer = bench_timer;

	if (unlikely(!handshake->static_identity->has_initiator_identity || !handshake->has_responder_public))
		goto out;

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);

	// compute C1, H1, H2
	handshake_init(handshake->chaining_key, handshake->hash,
		       handshake->remote_static_public_responder);

	DEBUG_PRINT_KEY("client C2", handshake->chaining_key, NOISE_HASH_LEN);
	DEBUG_PRINT_KEY("client H2", handshake->hash, NOISE_HASH_LEN);

	// XXX: this is where the PQWG paper does Twisted PRF

	/* e */
	if (!rkem_ephemeral_keygen(dst->unencrypted_ephemeral, handshake->ephemeral_private, handshake->static_identity->initiator_public, &handshake->rkem_buf)) {
        pr_err("eror in ephemeral keygen");
		goto out;
    }

	// update transcript: computes H3, C2
	message_ephemeral(dst->unencrypted_ephemeral, handshake->chaining_key,
			  handshake->hash);

	DEBUG_PRINT_KEY("client C3", handshake->chaining_key, NOISE_HASH_LEN);
	DEBUG_PRINT_KEY("client H3", handshake->hash, NOISE_HASH_LEN);

	/* es */
	// encapsulate to static secret
	u8 shared_secret[KEM_SS_SIZE];
	if (!kem_encapsulate(shared_secret, dst->unencrypted_ciphertext, handshake->remote_static_public_responder, &handshake->kem_buf))
		goto out;

	DEBUG_PRINT_KEY("client es", shared_secret, sizeof(shared_secret));

	/* Compute H4 */
	mix_hash(handshake->hash, dst->unencrypted_ciphertext, KEM_CIPHERTEXT_SIZE);
    DEBUG_PRINT_KEY("client H4", handshake->hash, NOISE_HASH_LEN);

	/* compute C3 */
    mix_kem_ss(handshake->chaining_key, key, shared_secret);

	DEBUG_PRINT_KEY("client C4", handshake->chaining_key, NOISE_HASH_LEN);

	/* s */
    // aka ltk
	// updates transcript: computes H4
	message_encrypt(dst->encrypted_static,
			handshake->static_identity->initiator_public_hash,
			NOISE_PK_HASH_LEN, key, handshake->hash);

    mix_key_chain_only(handshake->chaining_key, handshake->static_identity->initiator_public, NOISE_INITIATOR_PUBLIC_KEY_LEN);
    DEBUG_PRINT_KEY("client C5", handshake->chaining_key, NOISE_HASH_LEN);
    DEBUG_PRINT_KEY("client H5", handshake->hash, NOISE_HASH_LEN);

	/* psk */
	mix_psk(handshake->chaining_key, handshake->hash, handshake->key, handshake->preshared_key);

    DEBUG_PRINT_KEY("client C6", handshake->chaining_key, NOISE_HASH_LEN);
    DEBUG_PRINT_KEY("client H6", handshake->hash, NOISE_HASH_LEN);

	/* {t} */
	// updates transcript: H5
	tai64n_now(timestamp);
	message_encrypt(dst->encrypted_timestamp, timestamp,
			NOISE_TIMESTAMP_LEN, handshake->key, handshake->hash);

    DEBUG_PRINT_KEY("client H7", handshake->hash, NOISE_HASH_LEN);

	dst->sender_index = wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry);

	handshake->state = HANDSHAKE_CREATED_INITIATION;
	ret = true;

out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(shared_secret, sizeof(shared_secret));
	return ret;
}

struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
				      struct wg_device *wg)
{
	struct wg_peer *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	bool replay_attack, flood_attack;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 s_hash[NOISE_PK_HASH_LEN];
//	u8 e[NOISE_EPHEMERAL_PUBLIC_KEY_LEN];
//	u8 ct[NOISE_INITIAL_CIPHERTEXT_LEN];
	u8 static_shared_secret[KEM_SS_SIZE];
	u8 t[NOISE_TIMESTAMP_LEN];
	u64 initiation_consumption;
	u64 bench_timer = ktime_get_ns();

	// pr_debug("Server consuming initial msg");

	down_read(&wg->static_identity.lock);
	if (unlikely(!wg->static_identity.has_responder_identity))
		goto out;

	// compute H1, H2, C1, C2
	handshake_init(chaining_key, hash, wg->static_identity.responder_public);

	DEBUG_PRINT_KEY("server C2", chaining_key, NOISE_HASH_LEN);
	DEBUG_PRINT_KEY("server H2", hash, NOISE_HASH_LEN);

	/* e */
	// hash C3, H3
	message_ephemeral(src->unencrypted_ephemeral, chaining_key, hash);

	DEBUG_PRINT_KEY("server C3", chaining_key, NOISE_HASH_LEN);
	DEBUG_PRINT_KEY("server H3", hash, NOISE_HASH_LEN);

	// pr_debug("decapsulate");

	/* es */
	// we need a mcelice buffer but don't have a handshake yet
	// grab a random peer
#ifdef KEM_USES_BUFFER
	peer = wg_pubkey_hashtable_random_free(wg->peer_hashtable);
	if (!peer) goto out;
	struct kem_buffer *kem_buf = &peer->handshake.kem_buf; 
#else
	struct kem_buffer *kem_buf = NULL;
#endif

	// Decapsulate
	if (!kem_decapsulate(static_shared_secret, src->unencrypted_ciphertext, wg->static_identity.responder_private, kem_buf)) {
#ifdef KEM_USES_BUFFER
		up_write(&peer->handshake.lock);
		wg_peer_put(peer);
#endif
		goto out;
	}
#ifdef KEM_USES_BUFFER
	up_write(&peer->handshake.lock); // release write lock of random peer
	wg_peer_put(peer);
#endif
	peer = NULL;

	DEBUG_PRINT_KEY("server es", static_shared_secret, sizeof(static_shared_secret));

	/* Compute C4, H4 */
	mix_hash(hash, src->unencrypted_ciphertext, KEM_CIPHERTEXT_SIZE);

    DEBUG_PRINT_KEY("server H4", hash, NOISE_HASH_LEN);

	// compute C4
	mix_kem_ss(chaining_key, key, static_shared_secret);
	DEBUG_PRINT_KEY("server C4", chaining_key, NOISE_HASH_LEN);

	/* s */
	// pr_debug("decrypt");
	// recover H(pk)
	if (!message_decrypt(s_hash, src->encrypted_static,
			     sizeof(src->encrypted_static), key, hash))
		goto out;

    DEBUG_PRINT_KEY("server H5", hash, NOISE_HASH_LEN);

	/* Lookup which initiator peer we're actually talking to */
	peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable, s_hash);
	// pr_debug("Found peer: %d", !!peer);
	//if (peer)
	//	pr_debug("Peer has initiator_public: %d", peer->handshake.has_initiator_public);
	if (!peer || !peer->handshake.has_initiator_public) {
        pr_err("No peer!");
		goto out;
    }
	handshake = &peer->handshake;

    mix_key_chain_only(chaining_key, handshake->remote_static_public_initiator, NOISE_INITIATOR_PUBLIC_KEY_LEN);
    DEBUG_PRINT_KEY("server C5", chaining_key, NOISE_HASH_LEN);

	/* psk */
	mix_psk(chaining_key, hash, key, handshake->preshared_key);

    DEBUG_PRINT_KEY("server C6", chaining_key, NOISE_HASH_LEN);
    DEBUG_PRINT_KEY("server H6", hash, NOISE_HASH_LEN);

	// /* ss */
	// if (!mix_precomputed_dh(chaining_key, key,
	// 			handshake->precomputed_static_static))
	//     goto out;

	/* {t} */
	// pr_debug("decrypt timestamp");
	if (!message_decrypt(t, src->encrypted_timestamp,
			     sizeof(src->encrypted_timestamp), key, hash))
		goto out;

    DEBUG_PRINT_KEY("server H7", hash, NOISE_HASH_LEN);

	down_read(&handshake->lock);
	replay_attack = memcmp(t, handshake->latest_timestamp,
			       NOISE_TIMESTAMP_LEN) <= 0;
	flood_attack = (s64)handshake->last_initiation_consumption +
			       NSEC_PER_SEC / INITIATIONS_PER_SECOND >
		       (s64)ktime_get_coarse_boottime_ns();
	up_read(&handshake->lock);
	if (replay_attack || flood_attack)
		goto out;

	// pr_debug("success");

	/* Success! Copy everything to peer */
	down_write(&handshake->lock);
	handshake->bench_timer = bench_timer;
	memcpy(handshake->remote_static_initiator_hash, s_hash, NOISE_PK_HASH_LEN);
	memcpy(handshake->ephemeral_public, src->unencrypted_ephemeral, NOISE_EPHEMERAL_PUBLIC_KEY_LEN);
	if (memcmp(t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
		memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
    memcpy(handshake->key, key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	initiation_consumption = ktime_get_coarse_boottime_ns();
	if ((s64)(handshake->last_initiation_consumption - initiation_consumption) < 0)
		handshake->last_initiation_consumption = initiation_consumption;
	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
	up_write(&handshake->lock);
	ret_peer = peer;

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	memzero_explicit(static_shared_secret, KEM_SS_SIZE);
	up_read(&wg->static_identity.lock);
	if (!ret_peer)
		wg_peer_put(peer);
	return ret_peer;
}

bool wg_noise_handshake_create_response(struct message_handshake_response *dst,
					struct noise_handshake *handshake)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;
	u64 timer_start;
	char remote_initiator_public_hash_hex[NOISE_PK_HASH_LEN*2 + 1];

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	wait_for_random_bytes();

	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

    memcpy(key, handshake->key, NOISE_HASH_LEN);
    DEBUG_PRINT_KEY("server ipublic", handshake->remote_static_public_initiator, 16);
	timer_start = handshake->bench_timer;

	if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE);
	dst->receiver_index = handshake->remote_index;

	/* e */
	u8 shared_secret[RKEM_SHARED_SECRET_BYTES];
    u8 ct[NOISE_RESPONSE_CIPHERTEXT_LEN];
	if (!rkem_encapsulate(shared_secret, ct, handshake->remote_static_public_initiator, handshake->ephemeral_public, &handshake->rkem_buf))
		goto out;

    DEBUG_PRINT_KEY("server key", key, 32);
	message_encrypt(dst->encrypted_ciphertext, ct, NOISE_RESPONSE_CIPHERTEXT_LEN, key, handshake->hash);

    DEBUG_PRINT_KEY("server ipublic", handshake->remote_static_public_initiator, 16);
    DEBUG_PRINT_KEY("server H8", handshake->hash, NOISE_HASH_LEN);

	/* ee */
    DEBUG_PRINT_KEY("server ss", shared_secret, RKEM_SHARED_SECRET_BYTES);
	mix_kem_ss(handshake->chaining_key, key, shared_secret);

    DEBUG_PRINT_KEY("server C7", handshake->chaining_key, NOISE_HASH_LEN);

	// /* se */
	// if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
	// 	    handshake->remote_ciphertext))
	// 	goto out;


	/* {} */
	message_encrypt(dst->encrypted_nothing, NULL, 0, key, handshake->hash);

	dst->sender_index = wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry);

	handshake->state = HANDSHAKE_CREATED_RESPONSE;
	ret = true;

    u64 time = ktime_get_ns() - timer_start;
	bin2hex(remote_initiator_public_hash_hex, handshake->remote_static_initiator_hash, NOISE_PK_HASH_LEN);
	remote_initiator_public_hash_hex[NOISE_PK_HASH_LEN*2] = '\0';

	pr_notice("server to [%s] completed handshake in %llu ns", remote_initiator_public_hash_hex, time);

out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(shared_secret, RKEM_SHARED_SECRET_BYTES);
	return ret;
}

struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
				    struct wg_device *wg)
{
	enum noise_handshake_state state = HANDSHAKE_ZEROED;
	struct wg_peer *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	// u8 e[NOISE_RESPONSE_CIPHERTEXT_LEN];
	//u8 ephemeral_private[NOISE_EPHEMERAL_PRIVATE_KEY_LEN];
	//u8 static_private[NOISE_INITIATOR_PRIVATE_KEY_LEN];
	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 my_id_hash[NOISE_PK_HASH_LEN];
	char my_id_hex[NOISE_PK_HASH_LEN * 2 + 1];
	u64 timer_start;

	down_read(&wg->static_identity.lock);

	if (unlikely(!wg->static_identity.has_initiator_identity))
		goto out;

	handshake = (struct noise_handshake *)wg_index_hashtable_lookup(
		wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE,
		src->receiver_index, &peer);
	if (unlikely(!handshake))
		goto out;

	down_read(&handshake->lock);
	state = handshake->state;
	memcpy(my_id_hash, wg->static_identity.initiator_public_hash, NOISE_HASH_LEN);
	memcpy(hash, handshake->hash, NOISE_HASH_LEN);
	memcpy(key, handshake->key, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
	//memcpy(ephemeral_private, handshake->ephemeral_private, NOISE_EPHEMERAL_PRIVATE_KEY_LEN);
	memcpy(preshared_key, handshake->preshared_key,
	       NOISE_SYMMETRIC_KEY_LEN);
	timer_start = handshake->bench_timer;

	if (state != HANDSHAKE_CREATED_INITIATION) {
        up_read(&handshake->lock);
		goto fail;
    }

	/* e */
	//message_ephemeral(src->unencrypted_ciphertext, chaining_key, hash);
    u8 msg[NOISE_RESPONSE_CIPHERTEXT_LEN];
    DEBUG_PRINT_KEY("client key", key, 32);
    if (!message_decrypt(msg, src->encrypted_ciphertext, sizeof(src->encrypted_ciphertext), key, hash)) {
        pr_debug("decrypt failed");
        up_read(&handshake->lock);
        goto fail;
    }

    DEBUG_PRINT_KEY("client H8", hash, NOISE_HASH_LEN);

	u8 shared_secret[RKEM_SHARED_SECRET_BYTES];
	if (!rkem_decapsulate(shared_secret, msg, wg->static_identity.initiator_private, handshake->ephemeral_private, &handshake->rkem_buf)) {
        up_read(&handshake->lock);
		goto out;
    }

    DEBUG_PRINT_KEY("client ss", shared_secret, RKEM_SHARED_SECRET_BYTES);

    up_read(&handshake->lock);

	/* ee */
	// if (!mix_dh(chaining_key, NULL, ephemeral_private, e))
	// 	goto fail;
	mix_kem_ss(chaining_key, key, shared_secret);

    DEBUG_PRINT_KEY("client C7", chaining_key, NOISE_HASH_LEN);

	// /* se */
	// if (!mix_dh(chaining_key, NULL, wg->static_identity.initiator_private, e))
	// 	goto fail;

	/* {} */
	if (!message_decrypt(NULL, src->encrypted_nothing,
			     sizeof(src->encrypted_nothing), key, hash)) {
        pr_debug("decrypt failed");
		goto fail;
    }

	/* Success! Copy everything to peer */
	down_write(&handshake->lock);
	/* It's important to check that the state is still the same, while we
	 * have an exclusive lock.
	 */
	if (handshake->state != state) {
		up_write(&handshake->lock);
		goto fail;
	}
	// memcpy(handshake->remote_ciphertext, e, NOIS);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
	up_write(&handshake->lock);
	ret_peer = peer;

    u64 time = ktime_get_ns() - timer_start;
	bin2hex(my_id_hex, my_id_hash, NOISE_HASH_LEN);
	my_id_hex[NOISE_HASH_LEN*2] = '\0';

	pr_notice("client [%s] completed handshake in %llu ns", my_id_hex, time);

	goto out;

fail:
	wg_peer_put(peer);
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	//memzero_explicit(ephemeral_private, NOISE_EPHEMERAL_PRIVATE_KEY_LEN);
	//memzero_explicit(static_private, NOISE_INITIATOR_PRIVATE_KEY_LEN);
	memzero_explicit(preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	up_read(&wg->static_identity.lock);
	return ret_peer;
}

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
				      struct noise_keypairs *keypairs)
{
	struct noise_keypair *new_keypair;
	bool ret = false;

	down_write(&handshake->lock);
	if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
	    handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
		goto out;

	new_keypair = keypair_create(handshake->entry.peer);
	if (!new_keypair)
		goto out;
	new_keypair->i_am_the_initiator = handshake->state ==
					  HANDSHAKE_CONSUMED_RESPONSE;
	new_keypair->remote_index = handshake->remote_index;

	if (new_keypair->i_am_the_initiator)
		derive_keys(&new_keypair->sending, &new_keypair->receiving,
			    handshake->chaining_key);
	else
		derive_keys(&new_keypair->receiving, &new_keypair->sending,
			    handshake->chaining_key);

	handshake_zero(handshake);
	rcu_read_lock_bh();
	if (likely(!READ_ONCE(container_of(handshake, struct wg_peer,
					   handshake)->is_dead))) {
		add_new_keypair(keypairs, new_keypair);
		net_dbg_ratelimited("%s: Keypair %llu created for peer %llu\n",
				    handshake->entry.peer->device->dev->name,
				    new_keypair->internal_id,
				    handshake->entry.peer->internal_id);
		ret = wg_index_hashtable_replace(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry, &new_keypair->entry);
	} else {
		kfree_sensitive(new_keypair);
	}
	rcu_read_unlock_bh();

out:
	up_write(&handshake->lock);
	return ret;
}
