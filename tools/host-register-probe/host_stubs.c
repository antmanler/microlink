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

/* Node key rotation writes NVS on the device; the probe never reaches it
 * (it never sees NodeKeyExpired because every key is brand new). */
esp_err_t ml_identity_rotate_node_key(microlink_t *ml, uint8_t new_priv[32], uint8_t new_pub[32]) {
    (void)ml; (void)new_priv; (void)new_pub;
    return ESP_FAIL;
}
void ml_identity_clear_old_node_key(microlink_t *ml) { (void)ml; }

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
