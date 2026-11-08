/**
 * @file ml_peer_policy.c
 * @brief Priority peer by MagicDNS name, and peer table admission
 *
 * The peer table holds ML_MAX_PEERS peers in netmap order. A priority peer (by name,
 * microlink_set_priority_peer_name(), or by IP, CONFIG_ML_PRIORITY_PEER_IP) is always
 * admitted: when the table is full, the least recently active non-priority peer is
 * evicted. The coord task marks each netmap peer it parses, so the choice is applied
 * again on every netmap update.
 */

#include "microlink_internal.h"
#include <string.h>

static size_t name_len(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n > 0 && s[n - 1] == '.') n--;
    return n;
}

static char ascii_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* DNS names compare case-insensitively (RFC 4343); a trailing dot is ignored. */
bool ml_dns_name_equal(const char *a, const char *b) {
    size_t la = name_len(a), lb = name_len(b);
    if (la == 0 || la != lb) return false;
    for (size_t i = 0; i < la; i++) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    }
    return true;
}

esp_err_t microlink_set_priority_peer_name(microlink_t *ml, const char *fqdn) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    size_t len = name_len(fqdn);
    if (len > ML_DNS_NAME_MAX) return ESP_ERR_INVALID_ARG;

    bool changed;
    portENTER_CRITICAL(&ml->id_lock);
    changed = len == 0 ? ml->priority_name[0] != '\0'
                       : !ml_dns_name_equal(ml->priority_name, fqdn);
    if (changed) {
        if (len) memcpy(ml->priority_name, fqdn, len);
        ml->priority_name[len] = '\0';
    }
    portEXIT_CRITICAL(&ml->id_lock);

    /* A peer left out of the table is only known again from a full netmap. */
    microlink_state_t st = ml->state;
    if (changed && len > 0 && ml->coord_cmd_queue &&
        (st == ML_STATE_CONNECTED || st == ML_STATE_NEEDS_MACHINE_AUTH)) {
        ml_coord_cmd_t cmd = ML_CMD_RESYNC_NETMAP;
        xQueueSend(ml->coord_cmd_queue, &cmd, 0);
    }
    return ESP_OK;
}

void ml_copy_priority_name(microlink_t *ml, char *buf, size_t len) {
    if (!buf || len == 0) return;
    portENTER_CRITICAL(&ml->id_lock);
    strncpy(buf, ml->priority_name, len - 1);
    buf[len - 1] = '\0';
    portEXIT_CRITICAL(&ml->id_lock);
}

/* Slot for a new peer: a free one; else, for a priority peer only, a non-priority
 * peer (*evict = true): one without a WireGuard session first, then the least
 * recently active. A peer with a live session goes only when no other candidate
 * exists. -1 when the peer is not admitted. */
int ml_peer_admit_slot(const ml_peer_t *peers, int max, bool incoming_priority, bool *evict) {
    *evict = false;
    for (int i = 0; i < max; i++) {
        if (!peers[i].active) return i;
    }
    if (!incoming_priority) return -1;

    int victim = -1;
    uint64_t oldest = UINT64_MAX;
    bool victim_session = true;
    for (int i = 0; i < max; i++) {
        if (peers[i].priority) continue;
        uint64_t last = peers[i].last_send_ms;
        if (peers[i].last_pong_recv_ms > last) last = peers[i].last_pong_recv_ms;
        bool better = victim < 0 ||
                      (victim_session && !peers[i].has_session) ||
                      (victim_session == peers[i].has_session && last < oldest);
        if (better) {
            oldest = last;
            victim = i;
            victim_session = peers[i].has_session;
        }
    }
    if (victim >= 0) *evict = true;
    return victim;
}
