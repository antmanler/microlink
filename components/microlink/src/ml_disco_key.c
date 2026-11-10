/**
 * @file ml_disco_key.c
 * @brief Per-peer cache of the NaCl box key for DISCO; the contract is at ml_peer_t.
 *
 * No FreeRTOS or lwIP, so the host tests (tools/host-register-probe) build it unchanged.
 */

#include "microlink_internal.h"
#include "nacl_box.h"
#include "mbedtls/platform_util.h"
#include <string.h>

/* Invalidate and wipe. */
void ml_peer_disco_cache_clear(ml_peer_t *p) {
    mbedtls_platform_zeroize(p->disco_shared_key, sizeof(p->disco_shared_key));
    p->disco_shared_valid = false;
}

/* Assign the peer's disco key; the cache stays valid only if the bytes are unchanged. */
void ml_peer_set_disco_key(ml_peer_t *p, const uint8_t disco_key[32]) {
    if (memcmp(p->disco_key, disco_key, 32) == 0) return;
    memcpy(p->disco_key, disco_key, 32);
    ml_peer_disco_cache_clear(p);
}

/* Copy the box key for peer p into out; the caller wipes it. With use_cache the key is
 * derived on first use and then served from the cache; without it the cache is untouched. */
void ml_peer_disco_box_key(ml_peer_t *p, const uint8_t our_disco_private_key[32],
                           bool use_cache, uint8_t out[32]) {
    if (!use_cache) {
        nacl_box_beforenm(out, p->disco_key, our_disco_private_key);
        return;
    }
    if (!p->disco_shared_valid) {
        nacl_box_beforenm(p->disco_shared_key, p->disco_key, our_disco_private_key);
        p->disco_shared_valid = true;
    }
    memcpy(out, p->disco_shared_key, 32);
}
