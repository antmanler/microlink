/**
 * Host replacements for the few microlink.c / ml_stun.c functions that
 * ml_coord.c links against. Everything else the probe runs is the firmware's
 * own code. None of these stubs touches the network or stores anything.
 */

#include "microlink_internal.h"
#include "esp_timer.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ESP_LOGx: silent by default. Set PROBE_LOG=1 to see what MicroLink logs
 * (it logs states and sizes only, never an AuthURL, see DESIGN section 7.4). */
void probe_log(char level, const char *tag, const char *fmt, ...) {
    static int enabled = -1;
    if (enabled < 0) enabled = getenv("PROBE_LOG") != NULL;
    if (!enabled) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%c (%s) ", level, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

uint64_t ml_get_time_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

const char *microlink_default_device_name(void) { return "microlink-p3-probe"; }

void microlink_ip_to_str(uint32_t ip, char *buf) {
    snprintf(buf, 16, "%u.%u.%u.%u", (unsigned)(ip & 0xFF), (unsigned)((ip >> 8) & 0xFF),
             (unsigned)((ip >> 16) & 0xFF), (unsigned)(ip >> 24));
}

/* Node key rotation writes NVS on the device. The stub mimics its RAM effects and lets a
 * test choose the outcome and count the calls. */
int stub_rotate_calls;
int stub_clear_calls;
esp_err_t stub_rotate_result = ESP_OK;

esp_err_t ml_identity_rotate_node_key(microlink_t *ml, uint8_t new_priv[32], uint8_t new_pub[32]) {
    stub_rotate_calls++;
    if (stub_rotate_result != ESP_OK) return stub_rotate_result;
    memset(new_priv, 0x11, 32);
    memset(new_pub, 0x22, 32);
    memcpy(ml->old_node_pub, ml->wg_public_key, 32);    /* a stale OLD_PUB is overwritten */
    ml->old_node_valid = true;
    return ESP_OK;
}

void ml_identity_clear_old_node_key(microlink_t *ml) {
    stub_clear_calls++;
    ml->old_node_valid = false;
    memset(ml->old_node_pub, 0, sizeof(ml->old_node_pub));
}

/* Records ml_coord_cmd_t values sent to stub_cmd_queue; other queues are ignored. */
void *stub_cmd_queue;
int stub_cmd_sent;
int stub_cmd_last = -1;
/* Peer updates sent to stub_peer_queue are kept for the test (it frees them). */
void *stub_peer_queue;
ml_peer_update_t *stub_peer_updates[64];
int stub_peer_update_count;
BaseType_t shim_queue_send(QueueHandle_t q, const void *item) {
    if (q != NULL && q == stub_cmd_queue) {
        stub_cmd_sent++;
        stub_cmd_last = *(const int *)item;
        return pdTRUE;
    }
    if (q != NULL && q == stub_peer_queue && stub_peer_update_count < 64) {
        stub_peer_updates[stub_peer_update_count++] = *(ml_peer_update_t *const *)item;
        return pdTRUE;
    }
    return pdFALSE;
}

/* DERP latency probes (ml_netcheck.c): recorded so a test can answer them. */
int stub_binding_sent;
uint32_t stub_binding_ip[256];
uint8_t stub_binding_txid[256][12];
esp_err_t ml_stun_send_binding(microlink_t *ml, uint32_t ip, uint16_t port, uint8_t txid[12]) {
    (void)ml; (void)port;
    for (int i = 0; i < 12; i++) txid[i] = (uint8_t)(stub_binding_sent * 13 + i + 1);
    if (stub_binding_sent < 256) {
        stub_binding_ip[stub_binding_sent] = ip;
        memcpy(stub_binding_txid[stub_binding_sent], txid, 12);
    }
    stub_binding_sent++;
    return ESP_OK;
}

/* STUN is not part of the registration path. */
esp_err_t ml_stun_resolve_servers(microlink_t *ml) { (void)ml; return ESP_FAIL; }
esp_err_t ml_stun_send_probe(microlink_t *ml, const char *s, uint16_t p) { (void)ml; (void)s; (void)p; return ESP_FAIL; }
esp_err_t ml_stun_send_probe_to(microlink_t *ml, uint32_t s, uint16_t p) { (void)ml; (void)s; (void)p; return ESP_FAIL; }
esp_err_t ml_stun_send_probe_ipv6(microlink_t *ml, const uint8_t *s, uint16_t p) { (void)ml; (void)s; (void)p; return ESP_FAIL; }
bool ml_stun_parse_response(const uint8_t *d, size_t n, uint32_t *ip, uint16_t *port) {
    (void)d; (void)n; (void)ip; (void)port; return false;
}
bool ml_stun_parse_response_ipv6(const uint8_t *d, size_t n, uint8_t *ip6, uint16_t *port) {
    (void)d; (void)n; (void)ip6; (void)port; return false;
}
