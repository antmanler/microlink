/**
 * Host tests of the DISCO box key path.
 *
 * Part 1 runs the real nacl_box.c and x25519.c: the published NaCl tests/box.c vector, and
 * the agreement of the one-shot calls (nacl_box, nacl_box_open) with the precomputed-key calls
 * (nacl_box_beforenm + nacl_box_afternm / nacl_box_open_afternm), tampered boxes included.
 *
 * Part 2 runs the per-peer key cache, ml_disco_key.c. The file is #included so
 * nacl_box_beforenm() can be counted; nothing else is replaced.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "microlink_internal.h"
#include "nacl_box.h"
#include "x25519.h"

static int g_failed, g_total;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_total++;                                                           \
        if (!(cond)) {                                                       \
            g_failed++;                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

static int g_beforenm_calls;

static int counted_beforenm(uint8_t *shared_key, const uint8_t *recipient_pk,
                            const uint8_t *sender_sk) {
    g_beforenm_calls++;
    return nacl_box_beforenm(shared_key, recipient_pk, sender_sk);
}

#define nacl_box_beforenm counted_beforenm
#include "ml_disco_key.c"
#undef nacl_box_beforenm

static bool all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static uint8_t rng_byte(void) {         /* xorshift64*, deterministic */
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    return (uint8_t)((g_rng * 0x2545F4914F6CDD1Dull) >> 56);
}

typedef struct { uint8_t sk[32], pk[32]; } keypair_t;

static void random_keypair(keypair_t *k) {
    for (int i = 0; i < 32; i++) k->sk[i] = rng_byte();
    x25519_base(k->pk, k->sk, 1);
}

/* ============================================================================
 * Part 1: nacl_box.c
 * ========================================================================== */

/* NaCl tests/box.c (also libsodium test/default/box.c): crypto_box(c, m, bobpk, alicesk).
 * The keys are the Alice and Bob pairs of RFC 7748 section 6.1; nacl_key is the box key. */
static const uint8_t nacl_sk[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
    0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};
static const uint8_t nacl_pk[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2,
    0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
static const uint8_t nacl_peer_sk[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b,
    0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};
static const uint8_t nacl_sender_pk[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc,
    0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};
static const uint8_t nacl_nonce[24] = {
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
    0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};
static const uint8_t nacl_key[32] = {
    0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
    0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
    0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
};
static const uint8_t nacl_msg[131] = {
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
    0xeb, 0xeb, 0x0c, 0x7b, 0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
    0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf,
    0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce,
    0x31, 0x4a, 0xdb, 0x31, 0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
    0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a,
    0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c,
    0x60, 0x90, 0x2e, 0x52, 0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
    0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64, 0x5e, 0x07, 0x05
};
static const size_t nacl_msg_len = 131;
static const uint8_t nacl_ct[147] = {
    0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b,
    0x3d, 0x33, 0x05, 0xd9, 0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
    0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7,
    0x16, 0x4d, 0x96, 0xa4, 0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
    0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7, 0xf0, 0x11,
    0xec, 0x48, 0xc9, 0x72, 0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
    0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3,
    0x14, 0xa7, 0xcc, 0x8a, 0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
    0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73,
    0x2b, 0xc0, 0xe9, 0xda, 0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
    0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22,
    0xa4, 0x3d, 0x14, 0xa6, 0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
    0xe3, 0x55, 0xa5
};

static void test_nacl_vector(void) {
    size_t n = nacl_msg_len, ct_len = n + NACL_BOX_MACBYTES;
    uint8_t ct[256], ct2[256], pt[256], key[32], key_rev[32];

    /* The key, from either side of the pair. */
    memset(key, 0, sizeof(key));
    CHECK(nacl_box_beforenm(key, nacl_pk, nacl_sk) == 0);
    CHECK(memcmp(key, nacl_key, 32) == 0);
    CHECK(nacl_box_beforenm(key_rev, nacl_sender_pk, nacl_peer_sk) == 0);
    CHECK(memcmp(key_rev, nacl_key, 32) == 0);

    /* Seal: one-shot, precomputed key, and the published bytes. */
    memset(ct, 0xAA, sizeof(ct));
    memset(ct2, 0x55, sizeof(ct2));
    CHECK(nacl_box(ct, nacl_msg, n, nacl_nonce, nacl_pk, nacl_sk) == 0);
    CHECK(nacl_box_afternm(ct2, nacl_msg, n, nacl_nonce, key) == 0);
    CHECK(memcmp(ct, nacl_ct, ct_len) == 0);
    CHECK(memcmp(ct2, nacl_ct, ct_len) == 0);

    /* Open: one-shot from the recipient's side, precomputed key from the sender's side. */
    memset(pt, 0xAA, sizeof(pt));
    CHECK(nacl_box_open(pt, nacl_ct, ct_len, nacl_nonce, nacl_sender_pk, nacl_peer_sk) == 0);
    CHECK(memcmp(pt, nacl_msg, n) == 0);
    memset(pt, 0x55, sizeof(pt));
    CHECK(nacl_box_open_afternm(pt, nacl_ct, ct_len, nacl_nonce, key) == 0);
    CHECK(memcmp(pt, nacl_msg, n) == 0);

    /* Tampering: every part of the box, the nonce, the key, a wrong secret, too-short input. */
    uint8_t bad[256];
    size_t spots[] = { 0, 15, 16, ct_len - 1 };
    for (size_t s = 0; s < sizeof(spots) / sizeof(spots[0]); s++) {
        for (int bit = 0; bit < 8; bit += 7) {  /* low and high bit */
            memcpy(bad, nacl_ct, ct_len);
            bad[spots[s]] ^= (uint8_t)(1u << bit);
            CHECK(nacl_box_open(pt, bad, ct_len, nacl_nonce, nacl_sender_pk, nacl_peer_sk) == -1);
            CHECK(nacl_box_open_afternm(pt, bad, ct_len, nacl_nonce, key) == -1);
        }
    }
    uint8_t bad_nonce[24], bad_key[32];
    memcpy(bad_nonce, nacl_nonce, 24);
    bad_nonce[23] ^= 1;
    CHECK(nacl_box_open(pt, nacl_ct, ct_len, bad_nonce, nacl_sender_pk, nacl_peer_sk) == -1);
    CHECK(nacl_box_open_afternm(pt, nacl_ct, ct_len, bad_nonce, key) == -1);
    memcpy(bad_nonce, nacl_nonce, 24);
    bad_nonce[0] ^= 0x80;           /* the HSalsa20 half of the nonce */
    CHECK(nacl_box_open_afternm(pt, nacl_ct, ct_len, bad_nonce, key) == -1);
    memcpy(bad_key, key, 32);
    bad_key[31] ^= 1;
    CHECK(nacl_box_open_afternm(pt, nacl_ct, ct_len, nacl_nonce, bad_key) == -1);
    CHECK(nacl_box_open(pt, nacl_ct, ct_len, nacl_nonce, nacl_pk, nacl_pk) == -1);   /* wrong secret */
    CHECK(nacl_box_open(pt, nacl_ct, NACL_BOX_MACBYTES - 1, nacl_nonce, nacl_sender_pk, nacl_peer_sk) == -1);
    CHECK(nacl_box_open_afternm(pt, nacl_ct, 0, nacl_nonce, key) == -1);
}

/* Self-consistency over keys, nonces and lengths the vector does not cover. */
static void test_paths_agree(void) {
    for (int iter = 0; iter < 96; iter++) {
        keypair_t a, b;
        uint8_t nonce[24], msg[300];
        random_keypair(&a);
        random_keypair(&b);
        for (int i = 0; i < 24; i++) nonce[i] = rng_byte();
        size_t n = (size_t)(iter * 7) % 257;
        for (size_t i = 0; i < n; i++) msg[i] = rng_byte();

        uint8_t k_ab[32], k_ba[32], ct1[300 + 16], ct2[300 + 16], pt1[300], pt2[300];
        CHECK(nacl_box_beforenm(k_ab, b.pk, a.sk) == 0);
        CHECK(nacl_box_beforenm(k_ba, a.pk, b.sk) == 0);
        CHECK(memcmp(k_ab, k_ba, 32) == 0);

        CHECK(nacl_box(ct1, msg, n, nonce, b.pk, a.sk) == 0);
        CHECK(nacl_box_afternm(ct2, msg, n, nonce, k_ab) == 0);
        CHECK(memcmp(ct1, ct2, n + 16) == 0);

        memset(pt1, 0, sizeof(pt1));
        memset(pt2, 0xFF, sizeof(pt2));
        CHECK(nacl_box_open(pt1, ct1, n + 16, nonce, a.pk, b.sk) == 0);
        CHECK(nacl_box_open_afternm(pt2, ct1, n + 16, nonce, k_ba) == 0);
        CHECK(memcmp(pt1, msg, n) == 0);
        CHECK(memcmp(pt2, msg, n) == 0);

        ct1[(size_t)iter % (n + 16)] ^= 0x10;
        CHECK(nacl_box_open(pt1, ct1, n + 16, nonce, a.pk, b.sk) == -1);
        CHECK(nacl_box_open_afternm(pt2, ct1, n + 16, nonce, k_ba) == -1);
    }
}

/* ============================================================================
 * Part 2: the cache
 * ========================================================================== */

/* A peer whose disco key is pk. */
static void peer_with(ml_peer_t *p, const uint8_t pk[32]) {
    memset(p, 0, sizeof(*p));
    memcpy(p->disco_key, pk, 32);
}

static void test_first_use_computes_once(void) {
    ml_peer_t p;
    uint8_t key[32];
    peer_with(&p, nacl_pk);
    CHECK(!p.disco_shared_valid);

    g_beforenm_calls = 0;
    ml_peer_disco_box_key(&p, nacl_sk, true, key);
    CHECK(g_beforenm_calls == 1);
    CHECK(memcmp(key, nacl_key, 32) == 0);          /* the published NaCl key */
    CHECK(p.disco_shared_valid);
    CHECK(memcmp(p.disco_shared_key, nacl_key, 32) == 0);

    memset(key, 0, sizeof(key));
    for (int i = 0; i < 5; i++) {
        ml_peer_disco_box_key(&p, nacl_sk, true, key);
        CHECK(memcmp(key, nacl_key, 32) == 0);
    }
    CHECK(g_beforenm_calls == 1);                   /* five more uses, no more X25519 */
}

static void test_cached_key_seals_and_opens(void) {
    /* The cache on each side, the plain one-shot API on the other. */
    ml_peer_t sender, recipient;
    uint8_t k_sender[32], k_recipient[32], ct[300], pt[300];
    peer_with(&sender, nacl_pk);                    /* the sender's peer is the recipient */
    peer_with(&recipient, nacl_sender_pk);

    ml_peer_disco_box_key(&sender, nacl_sk, true, k_sender);
    ml_peer_disco_box_key(&recipient, nacl_peer_sk, true, k_recipient);
    CHECK(memcmp(k_sender, k_recipient, 32) == 0);

    CHECK(nacl_box_afternm(ct, nacl_msg, nacl_msg_len, nacl_nonce, k_sender) == 0);
    CHECK(memcmp(ct, nacl_ct, nacl_msg_len + 16) == 0);
    CHECK(nacl_box_open(pt, ct, nacl_msg_len + 16, nacl_nonce, nacl_sender_pk, nacl_peer_sk) == 0);
    CHECK(memcmp(pt, nacl_msg, nacl_msg_len) == 0);
    CHECK(nacl_box(ct, nacl_msg, nacl_msg_len, nacl_nonce, nacl_pk, nacl_sk) == 0);
    memset(pt, 0, sizeof(pt));
    CHECK(nacl_box_open_afternm(pt, ct, nacl_msg_len + 16, nacl_nonce, k_recipient) == 0);
    CHECK(memcmp(pt, nacl_msg, nacl_msg_len) == 0);
}

static void test_same_key_refresh_keeps_cache(void) {
    keypair_t ours, theirs;
    ml_peer_t p;
    uint8_t key[32], want[32];
    random_keypair(&ours);
    random_keypair(&theirs);
    nacl_box_beforenm(want, theirs.pk, ours.sk);
    peer_with(&p, theirs.pk);
    g_beforenm_calls = 0;
    ml_peer_disco_box_key(&p, ours.sk, true, key);
    CHECK(g_beforenm_calls == 1);

    /* A netmap refresh of a known peer repeats its disco key. */
    uint8_t same[32];
    memcpy(same, theirs.pk, 32);
    ml_peer_set_disco_key(&p, same);
    CHECK(p.disco_shared_valid);
    CHECK(memcmp(p.disco_shared_key, want, 32) == 0);
    ml_peer_disco_box_key(&p, ours.sk, true, key);
    CHECK(memcmp(key, want, 32) == 0);
    CHECK(g_beforenm_calls == 1);
}

static void test_changed_key_invalidates(void) {
    keypair_t ours, a, b;
    ml_peer_t p;
    uint8_t key[32], key_a[32], key_b[32];
    random_keypair(&ours);
    random_keypair(&a);
    random_keypair(&b);
    nacl_box_beforenm(key_a, a.pk, ours.sk);
    nacl_box_beforenm(key_b, b.pk, ours.sk);
    CHECK(memcmp(key_a, key_b, 32) != 0);

    peer_with(&p, a.pk);
    g_beforenm_calls = 0;
    ml_peer_disco_box_key(&p, ours.sk, true, key);
    CHECK(memcmp(key, key_a, 32) == 0);
    CHECK(g_beforenm_calls == 1);

    ml_peer_set_disco_key(&p, b.pk);
    CHECK(memcmp(p.disco_key, b.pk, 32) == 0);
    CHECK(!p.disco_shared_valid);
    CHECK(all_zero(p.disco_shared_key, 32));        /* wiped, not just flagged */

    ml_peer_disco_box_key(&p, ours.sk, true, key);
    CHECK(g_beforenm_calls == 2);
    CHECK(memcmp(key, key_b, 32) == 0);
    CHECK(p.disco_shared_valid);

    /* One changed byte is enough, wherever it is. */
    for (int pos = 0; pos < 32; pos += 31) {
        uint8_t k2[32], want[32];
        memcpy(k2, p.disco_key, 32);
        k2[pos] ^= 1;
        ml_peer_set_disco_key(&p, k2);
        CHECK(!p.disco_shared_valid);
        ml_peer_disco_box_key(&p, ours.sk, true, key);
        nacl_box_beforenm(want, k2, ours.sk);
        CHECK(memcmp(key, want, 32) == 0);
    }
}

static void test_cleared_slot_is_invalid_and_wiped(void) {
    ml_peer_t p;
    uint8_t key[32];
    peer_with(&p, nacl_pk);
    ml_peer_disco_box_key(&p, nacl_sk, true, key);
    CHECK(p.disco_shared_valid);
    CHECK(!all_zero(p.disco_shared_key, 32));

    ml_peer_disco_cache_clear(&p);
    CHECK(!p.disco_shared_valid);
    CHECK(all_zero(p.disco_shared_key, 32));

    g_beforenm_calls = 0;
    ml_peer_disco_box_key(&p, nacl_sk, true, key);   /* recomputed, not stale */
    CHECK(g_beforenm_calls == 1);
    CHECK(memcmp(key, nacl_key, 32) == 0);

    /* ml_peer_nvs_load_all() memsets the peer it fills. */
    memset(&p, 0, sizeof(p));
    CHECK(!p.disco_shared_valid);
}

static void test_slot_reuse_never_inherits(void) {
    keypair_t ours, old_peer, new_peer;
    random_keypair(&ours);
    random_keypair(&old_peer);
    random_keypair(&new_peer);
    uint8_t key[32], want[32];
    nacl_box_beforenm(want, new_peer.pk, ours.sk);

    /* remove_peer clears the slot; add_peer clears it again for a new peer. */
    ml_peer_t p;
    peer_with(&p, old_peer.pk);
    ml_peer_disco_box_key(&p, ours.sk, true, key);
    p.active = false;
    ml_peer_disco_cache_clear(&p);
    ml_peer_disco_cache_clear(&p);
    ml_peer_set_disco_key(&p, new_peer.pk);
    ml_peer_disco_box_key(&p, ours.sk, true, key);
    CHECK(memcmp(key, want, 32) == 0);

    /* An evicted slot is only deactivated; add_peer clears it for the new peer. */
    peer_with(&p, old_peer.pk);
    ml_peer_disco_box_key(&p, ours.sk, true, key);
    p.active = false;
    ml_peer_disco_cache_clear(&p);
    ml_peer_set_disco_key(&p, new_peer.pk);
    CHECK(!p.disco_shared_valid);
    ml_peer_disco_box_key(&p, ours.sk, true, key);
    CHECK(memcmp(key, want, 32) == 0);
}

static void test_peers_are_independent(void) {
    keypair_t ours, a, b;
    ml_peer_t pa, pb;
    uint8_t ka[32], kb[32];
    random_keypair(&ours);
    random_keypair(&a);
    random_keypair(&b);
    peer_with(&pa, a.pk);
    peer_with(&pb, b.pk);
    g_beforenm_calls = 0;
    ml_peer_disco_box_key(&pa, ours.sk, true, ka);   /* one private key, two peers */
    ml_peer_disco_box_key(&pb, ours.sk, true, kb);
    CHECK(g_beforenm_calls == 2);
    CHECK(memcmp(ka, kb, 32) != 0);
    ml_peer_disco_cache_clear(&pa);
    CHECK(pb.disco_shared_valid);
    CHECK(memcmp(pb.disco_shared_key, kb, 32) == 0);
    ml_peer_disco_box_key(&pb, ours.sk, true, kb);
    CHECK(g_beforenm_calls == 2);
}

static void test_without_cache_never_touches_it(void) {
    ml_peer_t p;
    uint8_t key[32];

    /* A caller outside the wg_mgr task: derived each time, cache untouched. */
    peer_with(&p, nacl_pk);
    g_beforenm_calls = 0;
    ml_peer_disco_box_key(&p, nacl_sk, false, key);
    CHECK(memcmp(key, nacl_key, 32) == 0);
    ml_peer_disco_box_key(&p, nacl_sk, false, key);
    CHECK(g_beforenm_calls == 2);
    CHECK(!p.disco_shared_valid);
    CHECK(all_zero(p.disco_shared_key, 32));

    /* With a valid cache present it is neither read nor changed. */
    ml_peer_disco_box_key(&p, nacl_sk, true, key);
    CHECK(g_beforenm_calls == 3);
    uint8_t snapshot[32];
    memcpy(snapshot, p.disco_shared_key, 32);
    ml_peer_disco_box_key(&p, nacl_sk, false, key);
    CHECK(g_beforenm_calls == 4);
    CHECK(p.disco_shared_valid);
    CHECK(memcmp(p.disco_shared_key, snapshot, 32) == 0);
}

int main(void) {
    test_nacl_vector();
    test_paths_agree();

    test_first_use_computes_once();
    test_cached_key_seals_and_opens();
    test_same_key_refresh_keeps_cache();
    test_changed_key_invalidates();
    test_cleared_slot_is_invalid_and_wiped();
    test_slot_reuse_never_inherits();
    test_peers_are_independent();
    test_without_cache_never_touches_it();

    printf("%d disco-key checks, %d failed\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
