/**
 * @file ml_netcheck.c
 * @brief DERP home region by measured latency (tailscaled netcheck port)
 *
 * After a DERP map arrives, and then every STUN re-probe interval, the coord task
 * sends STUN binding requests to the regions' nodes and times the replies. The
 * lowest-latency region becomes home: the DERP connection and PreferredDERP follow it.
 *
 * Reference: tailscale.com v1.104.0 net/netcheck/netcheck.go
 *   makeProbePlanInitial / makeProbePlan  -> ml_nc_make_plan
 *   addReportHistoryAndSetPreferredDERP    -> ml_nc_pick_home
 * Differences: IPv4 probes only; no ICMP/HTTPS fallback; the choice uses this
 * round's latencies, not the five-minute best-latency history.
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "ml_netcheck";

#define STUN_HEADER_SIZE        20
#define STUN_BINDING_RESPONSE   0x0101
#define STUN_MAGIC_COOKIE       0x2112A442

/* ============================================================================
 * Pure parts
 * ========================================================================== */

bool ml_nc_node_can_stun(const ml_derp_node_t *n) {
    return n->stun_port >= 0 && n->stun_ipv4 != 0;
}

static bool region_skipped(const ml_derp_region_t *r) {
    return r->avoid || r->no_measure;
}

/* A re-parsed node with the same region, host name and IPv4 field keeps its
 * resolved address: no repeated DNS lookup for every netmap. */
void ml_nc_keep_resolved(ml_derp_node_t *n, uint16_t region_id,
                         const ml_derp_region_t *old, int old_count) {
    for (int i = 0; i < old_count; i++) {
        if (old[i].region_id != region_id) continue;
        for (int j = 0; j < old[i].node_count; j++) {
            const ml_derp_node_t *o = &old[i].nodes[j];
            if (o->stun_ipv4 != 0 && !strcmp(o->hostname, n->hostname) &&
                !strcmp(o->ipv4, n->ipv4)) {
                n->stun_ipv4 = o->stun_ipv4;
                return;
            }
        }
        return;
    }
}

bool ml_nc_region_can_home(const ml_derp_region_t *r) {
    if (region_skipped(r) || r->derp_failed) return false;
    for (int i = 0; i < r->node_count; i++) {
        if (!r->nodes[i].stun_only && r->nodes[i].hostname[0]) return true;
    }
    return false;
}

static int stun_nodes(const ml_derp_region_t *r, uint8_t *idx) {
    int n = 0;
    for (int i = 0; i < r->node_count; i++) {
        if (ml_nc_node_can_stun(&r->nodes[i])) idx[n++] = (uint8_t)i;
    }
    return n;
}

static uint32_t last_latency(const ml_nc_sample_t *last, int last_count, uint16_t id) {
    for (int i = 0; i < last_count; i++) {
        if (last[i].region_id == id) return last[i].latency_us;
    }
    return 0;
}

static int add_probes(const ml_derp_region_t *regions, int ri, int tries, uint32_t prev_us,
                      bool initial, ml_nc_probe_t *out, int n, int max) {
    uint8_t nodes[ML_MAX_DERP_NODES];
    int nn = stun_nodes(&regions[ri], nodes);
    if (nn == 0) return n;
    for (int t = 0; t < tries && n < max; t++) {
        ml_nc_probe_t *p = &out[n++];
        memset(p, 0, sizeof(*p));
        p->region = (uint8_t)ri;
        p->node = nodes[t % nn];
        if (initial) {
            p->delay_us = (uint32_t)t * ML_NC_INITIAL_RETRANSMIT_MS * 1000u;
        } else {
            p->delay_us = (uint32_t)t * prev_us;
            if (t > 1) p->delay_us += (uint32_t)t * ML_NC_RETRANSMIT_STEP_MS * 1000u;
        }
    }
    return n;
}

int ml_nc_make_plan(const ml_derp_region_t *regions, int count,
                    const ml_nc_sample_t *last, int last_count, uint16_t home,
                    ml_nc_probe_t *out, int max) {
    int n = 0;
    if (last_count == 0) {
        /* makeProbePlanInitial: every region, three tries, 100 ms apart. */
        for (int ri = 0; ri < count; ri++) {
            if (region_skipped(&regions[ri])) continue;
            n = add_probes(regions, ri, ML_NC_INITIAL_TRIES, 0, true, out, n, max);
        }
        return n;
    }

    /* makeProbePlan: regions by last latency (replied first, fastest first). */
    uint8_t order[ML_MAX_DERP_REGIONS];
    int oc = 0;
    for (int ri = 0; ri < count && ri < ML_MAX_DERP_REGIONS; ri++) {
        if (!region_skipped(&regions[ri])) order[oc++] = (uint8_t)ri;
    }
    for (int i = 1; i < oc; i++) {           /* stable insertion sort */
        uint8_t v = order[i];
        uint32_t lv = last_latency(last, last_count, regions[v].region_id);
        int j = i - 1;
        while (j >= 0) {
            uint32_t lj = last_latency(last, last_count, regions[order[j]].region_id);
            bool v_first = lv != 0 && (lj == 0 || lv < lj);
            if (!v_first) break;
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = v;
    }

    bool plan_has_home = (home == 0);
    for (int k = 0; k < oc; k++) {
        int ri = order[k];
        bool is_home = regions[ri].region_id == home;
        if (k >= ML_NC_INCREMENTAL_REGIONS) {
            if (plan_has_home) break;
            if (!is_home) continue;
        }
        int tries = 1;
        if (k < ML_NC_FASTEST_REGIONS || is_home) tries = ML_NC_FASTEST_TRIES;
        if (is_home) {
            tries = ML_NC_HOME_TRIES;
            plan_has_home = true;
        }
        uint32_t prev_us = last_latency(last, last_count, regions[ri].region_id) *
                           ML_NC_RETRANSMIT_PCT / 100u;
        if (prev_us == 0) prev_us = ML_NC_ACTIVE_RETRANSMIT_MS * 1000u;
        n = add_probes(regions, ri, tries, prev_us, false, out, n, max);
    }
    return n;
}

static int region_index(const ml_derp_region_t *regions, int count, uint16_t id) {
    if (id == 0) return -1;
    for (int i = 0; i < count; i++) {
        if (regions[i].region_id == id) return i;
    }
    return -1;
}

uint16_t ml_nc_fallback_home(const ml_derp_region_t *regions, int count, uint16_t prev) {
    if (count == 0) return prev;              /* no map: nothing better to say */
    int pi = region_index(regions, count, prev);
    if (pi >= 0 && ml_nc_region_can_home(&regions[pi])) return prev;
    for (int i = 0; i < count; i++) {
        if (ml_nc_region_can_home(&regions[i])) return regions[i].region_id;
    }
    return count > 0 ? regions[0].region_id : 0;
}

uint16_t ml_nc_pick_home(const ml_derp_region_t *regions, int count, const uint32_t *lat_us,
                         uint16_t prev, bool prev_heard_recently) {
    int best = -1;
    for (int i = 0; i < count; i++) {
        if (lat_us[i] == 0 || !ml_nc_region_can_home(&regions[i])) continue;
        if (best < 0 || lat_us[i] < lat_us[best]) best = i;
    }
    if (best < 0) return ml_nc_fallback_home(regions, count, prev);   /* no reply */

    uint16_t best_id = regions[best].region_id;
    int pi = region_index(regions, count, prev);
    if (pi < 0 || pi == best || !ml_nc_region_can_home(&regions[pi])) return best_id;

    /* Stickiness: keep the old home while it is reachable and the new one is not
     * clearly better (absolute and relative thresholds). */
    int64_t old_us = lat_us[pi];
    int64_t best_us = lat_us[best];
    if (old_us == 0 && !prev_heard_recently) return best_id;
    if (old_us - best_us < ML_NC_ABS_DIFF_US) return prev;
    if (best_us > old_us / ML_NC_KEEP_DEN * ML_NC_KEEP_NUM) return prev;
    return best_id;
}

uint16_t ml_nc_effective_home(const ml_derp_region_t *regions, int count,
                              uint16_t peer_region, uint16_t latency_home) {
    /* We hold one DERP connection and send everything through our own home region,
     * so the priority peer is reachable over DERP only when our home is its home. */
    if (region_index(regions, count, peer_region) >= 0) return peer_region;
    return latency_home;
}

uint32_t ml_derp_backoff_ms(int failures, uint32_t rnd) {
    if (failures <= 0) return 0;
    uint64_t d = (uint64_t)failures * (uint64_t)failures * ML_DERP_BACKOFF_STEP_MS;
    if (d > ML_DERP_BACKOFF_MAX_MS) d = ML_DERP_BACKOFF_MAX_MS;
    /* util/backoff: d * (rand.Float64() + 0.5), i.e. 0.5x to 1.5x */
    return (uint32_t)(d / 2 + (d * (uint64_t)rnd >> 32));
}

bool ml_derp_backoff_capped(int failures) {
    return (uint64_t)failures * (uint64_t)failures * ML_DERP_BACKOFF_STEP_MS >= ML_DERP_BACKOFF_MAX_MS;
}

/* ============================================================================
 * Measurement round (coord task)
 * ========================================================================== */

static void free_round(ml_netcheck_t *nc) {
    free(nc->probes);
    nc->probes = NULL;
    nc->probe_count = 0;
    nc->open = false;
}

bool ml_netcheck_apply_home(microlink_t *ml) {
    ml_netcheck_t *nc = &ml->netcheck;
    uint16_t home = ml_nc_effective_home(ml->derp_regions, ml->derp_region_count,
                                         nc->peer_region, nc->latency_home);
    if (home == ml->derp_home_region) return false;
    ESP_LOGI(TAG, "Home DERP region %u -> %u (%s)", ml->derp_home_region, home,
             home == nc->peer_region ? "priority peer" : "latency");
    ml->derp_home_region = home;
    nc->home_changed = true;
    return true;
}

bool ml_netcheck_take_home_change(microlink_t *ml) {
    bool changed = ml->netcheck.home_changed;
    ml->netcheck.home_changed = false;
    return changed;
}

bool ml_netcheck_on_derp_map(microlink_t *ml) {
    ml_netcheck_t *nc = &ml->netcheck;
    free_round(nc);
    nc->next_full = true;
    nc->latency_home = ml_nc_fallback_home(ml->derp_regions, ml->derp_region_count,
                                           nc->latency_home);
    return ml_netcheck_apply_home(ml);
}

void ml_netcheck_request_full(microlink_t *ml) {
    ml->netcheck.next_full = true;
}

bool ml_netcheck_due(const microlink_t *ml, uint64_t now_ms) {
    const ml_netcheck_t *nc = &ml->netcheck;
    if (ml->derp_region_count == 0) return false;
    if (nc->next_full || !nc->ran) return true;
    return now_ms - nc->last_round_ms >= ml->t_stun_interval_ms;
}

/* Runs on the tcpip thread. The node is matched by name: the map may have been
 * re-parsed since the lookup started. */
static void dns_done(void *ctx, const char *host, uint32_t ipv4) {
    ml_derp_node_t *n = (ml_derp_node_t *)ctx;
    if (strcmp(n->hostname, host) == 0) {
        if (ipv4) n->stun_ipv4 = ipv4;
        else n->stun_dns_failed = true;            /* retried with the next map */
    }
    n->stun_dns_pending = false;
}

/* A literal IPv4 is used as is; anything else that is not empty disables IPv4
 * (tailcfg.DERPNode.IPv4, "none" by convention); empty means look up the host name.
 * Lookups never block the coord task: the node is probed once its address is in. */
static void resolve_node(ml_derp_node_t *n) {
    if (n->stun_ipv4 != 0 || n->stun_port < 0 || n->stun_dns_failed || n->stun_dns_pending) return;
    unsigned a, b, c, d;
    char extra;
    if (n->ipv4[0]) {
        if (sscanf(n->ipv4, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) == 4 &&
            a <= 255 && b <= 255 && c <= 255 && d <= 255) {
            n->stun_ipv4 = (a << 24) | (b << 16) | (c << 8) | d;
        }
        return;
    }
    if (!n->hostname[0]) return;
    n->stun_dns_pending = true;
    if (ml_stun_resolve_async(n->hostname, dns_done, n) != ESP_OK) {
        n->stun_dns_pending = false;
        n->stun_dns_failed = true;
    }
}

bool ml_netcheck_begin(microlink_t *ml, int64_t now_us) {
    ml_netcheck_t *nc = &ml->netcheck;
    uint64_t now_ms = (uint64_t)(now_us / 1000);
    free_round(nc);                 /* the previous round's late replies end here */
    memset(nc->lat_us, 0, sizeof(nc->lat_us));
    nc->start_us = now_us;

    bool full = nc->next_full || nc->last_count == 0 ||
                now_ms - nc->last_full_ms >= ML_NC_FULL_INTERVAL_MS;
    nc->next_full = false;
    nc->last_round_ms = now_ms;
    nc->ran = true;
    if (full) {
        nc->last_full_ms = now_ms;
        /* A full round gives regions whose DERP connects failed another chance. */
        for (int i = 0; i < ml->derp_region_count; i++) ml->derp_regions[i].derp_failed = false;
        ml->derp_failed_region = 0;
    }

    for (int i = 0; i < ml->derp_region_count; i++) {
        ml_derp_region_t *r = &ml->derp_regions[i];
        if (region_skipped(r)) continue;
        for (int j = 0; j < r->node_count; j++) resolve_node(&r->nodes[j]);
    }

    nc->probes = ml_psram_calloc(ML_NC_MAX_PROBES, sizeof(ml_nc_probe_t));
    if (!nc->probes) return false;
    nc->probe_count = ml_nc_make_plan(ml->derp_regions, ml->derp_region_count,
                                      nc->last, full ? 0 : nc->last_count,
                                      nc->latency_home, nc->probes, ML_NC_MAX_PROBES);
    ESP_LOGI(TAG, "Round: %s, %d probes", full ? "full" : "incremental", nc->probe_count);
    if (nc->probe_count == 0) {
        free_round(nc);
        return false;
    }
    nc->open = true;
    return true;
}

int32_t ml_netcheck_service(microlink_t *ml, int64_t now_us) {
    ml_netcheck_t *nc = &ml->netcheck;
    if (!nc->probes || !nc->open) return -1;
    int64_t elapsed = now_us - nc->start_us;
    int64_t timeout_us = (int64_t)ML_NC_STUN_TIMEOUT_MS * 1000;
    if (elapsed >= timeout_us) return -1;

    int64_t next_us = timeout_us - elapsed;
    bool waiting = false;     /* a planned region has not replied yet */
    int64_t clock0 = esp_timer_get_time();
    for (int i = 0; i < nc->probe_count; i++) {
        ml_nc_probe_t *p = &nc->probes[i];
        if (nc->lat_us[p->region] != 0) continue;     /* region done */
        waiting = true;
        if (p->sent) continue;
        if (p->delay_us > elapsed) {
            int64_t until = p->delay_us - elapsed;
            if (until < next_us) next_us = until;
            continue;
        }
        const ml_derp_node_t *n = &ml->derp_regions[p->region].nodes[p->node];
        uint16_t port = n->stun_port > 0 ? (uint16_t)n->stun_port : ML_STUN_DEFAULT_PORT;
        /* Taken right before the send: an earlier send may have blocked. */
        int64_t at = now_us + (esp_timer_get_time() - clock0);
        if (ml_stun_send_binding(ml, n->stun_ipv4, port, p->txid) == ESP_OK) {
            p->sent_us = at;
        }
        p->sent = true;       /* a failed send is not retried; the next try covers it */
    }
    if (!waiting) return -1;
    return (int32_t)((next_us + 999) / 1000);
}

/* rx_us: when the reply arrived (net I/O task), not when it was dequeued. A reply
 * to the previous round's probes (they are kept until the next round) is taken and
 * dropped, so it never reaches endpoint STUN. */
bool ml_netcheck_on_stun(microlink_t *ml, const uint8_t *data, size_t len, int64_t rx_us) {
    ml_netcheck_t *nc = &ml->netcheck;
    if (!nc->probes || len < STUN_HEADER_SIZE) return false;
    uint16_t type = (uint16_t)((data[0] << 8) | data[1]);
    uint32_t cookie = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                      ((uint32_t)data[6] << 8) | data[7];
    if (type != STUN_BINDING_RESPONSE || cookie != STUN_MAGIC_COOKIE) return false;
    for (int i = 0; i < nc->probe_count; i++) {
        ml_nc_probe_t *p = &nc->probes[i];
        if (!p->sent || p->sent_us == 0 || memcmp(p->txid, data + 8, 12) != 0) continue;
        if (!nc->open) return true;                     /* late: drop */
        int64_t rtt = rx_us - p->sent_us;
        uint32_t us = rtt > 0 ? (uint32_t)rtt : 1;     /* 0 means "no reply" */
        if (nc->lat_us[p->region] == 0 || us < nc->lat_us[p->region]) {
            nc->lat_us[p->region] = us;
        }
        return true;
    }
    return false;
}

void ml_netcheck_abort(microlink_t *ml) {
    free_round(&ml->netcheck);
    memset(ml->netcheck.lat_us, 0, sizeof(ml->netcheck.lat_us));
}

bool ml_netcheck_end(microlink_t *ml, int64_t now_us) {
    ml_netcheck_t *nc = &ml->netcheck;
    uint64_t now_ms = (uint64_t)(now_us / 1000);
    nc->open = false;               /* probes stay until the next round (late replies) */

    nc->last_count = 0;
    for (int i = 0; i < ml->derp_region_count; i++) {
        if (nc->lat_us[i] == 0) continue;
        nc->last[nc->last_count].region_id = ml->derp_regions[i].region_id;
        nc->last[nc->last_count].latency_us = nc->lat_us[i];
        nc->last_count++;
        ESP_LOGI(TAG, "  region %u: %lu us", ml->derp_regions[i].region_id,
                 (unsigned long)nc->lat_us[i]);
    }

    /* A region the DERP task cannot connect to is not a latency choice. */
    uint16_t failed = ml->derp_failed_region;
    for (int i = 0; failed && i < ml->derp_region_count; i++) {
        if (ml->derp_regions[i].region_id == failed) ml->derp_regions[i].derp_failed = true;
    }

    /* The old choice still counts as reachable when its DERP connection carried a
     * frame recently (PreferredDERPFrameTime). */
    uint16_t prev = nc->latency_home;
    bool heard = ml->derp.connected && ml->derp.region == prev &&
                 now_ms - ml->derp.last_recv_ms < ML_NC_FRAME_TIME_MS;
    nc->latency_home = ml_nc_pick_home(ml->derp_regions, ml->derp_region_count, nc->lat_us,
                                       prev, heard);
    ESP_LOGI(TAG, "Round done: %d regions replied, latency choice %u", nc->last_count,
             nc->latency_home);
    memset(nc->lat_us, 0, sizeof(nc->lat_us));
    ml_netcheck_apply_home(ml);
    return ml_netcheck_take_home_change(ml);
}
