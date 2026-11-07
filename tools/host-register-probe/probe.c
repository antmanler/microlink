/**
 * P3 probe: does the real Tailscale control server answer a keyless register
 * with an AuthURL?  (DESIGN docs/ambient-design/device-setup, section 10, P3.)
 *
 * What runs here is MicroLink's own code, compiled for the host:
 *   - ml_coord.c is #included below, so the probe calls the same static
 *     functions the coord task calls: do_tcp_connect, do_noise_handshake,
 *     process_proactive_frames, do_h2_preface, register_exchange, followup_open,
 *     register_poll;
 *   - the RegisterRequest is built by ml_register_build_request() and framed by
 *     ml_h2_build_*(), the Noise transport is ml_noise.c;
 *   - the response is classified by ml_register_parse_response().
 * Only the FreeRTOS / lwIP / ESP headers are shims (shim/), and the few
 * functions of microlink.c the coord code links against are in stubs.c.
 *
 * Output is states only. The AuthURL is a login capability: its value, path and
 * query are never printed, only its length and host. Keys are generated fresh
 * for every run and never stored, so the run adds no node to any tailnet: the
 * server records, at most, a registration that is waiting for a login nobody
 * will complete, and drops it when it expires.
 *
 * Usage: probe [--hostname NAME] [--ctrl-host HOST] [--followup-wait SECONDS]
 *   --followup-wait N  after the AuthURL, hold the Followup request for N seconds
 *                      (it must stay pending: the server answers it only when
 *                      someone finishes the login), then abandon it.
 * Exit 0: AuthURL received (and, with --followup-wait, the Followup stayed
 * pending). Exit 2: the server answered differently. Exit 1: transport failure.
 */

#include "microlink_internal.h"
#include "ml_register.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- capture the exact RegisterRequest body MicroLink builds ------------- */
static char *g_last_request;
static char *probe_build_request(const ml_register_req_t *req) {
    char *json = ml_register_build_request(req);
    free(g_last_request);
    g_last_request = json ? strdup(json) : NULL;
    return json;
}
#define ml_register_build_request probe_build_request

/* The firmware's own control-plane code, with its static functions. */
#include "ml_coord.c"

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("P3: ", stdout);
    vprintf(fmt, ap);
    fputc('\n', stdout);
    va_end(ap);
    fflush(stdout);
}

/* Field names of a JSON object, nested in braces. Values are never printed. */
static void shape(const cJSON *obj, char *out, size_t cap) {
    size_t n = 0;
    out[0] = '\0';
    for (const cJSON *c = obj ? obj->child : NULL; c; c = c->next) {
        n += snprintf(out + n, cap > n ? cap - n : 0, "%s%s", n ? "," : "", c->string ? c->string : "?");
        if (cJSON_IsObject(c)) {
            char inner[160];
            shape(c, inner, sizeof(inner));
            n += snprintf(out + n, cap > n ? cap - n : 0, "{%s}", inner);
        }
        if (n >= cap) break;
    }
}

static void gen_keypair(uint8_t priv[32], uint8_t pub[32]) {
    arc4random_buf(priv, 32);
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    x25519_base(pub, priv, 1);
}

/* "https://login.tailscale.com/a/xxxx" -> "login.tailscale.com"; path never leaves this function. */
static void url_host(const char *url, char *host, size_t cap, bool *https, bool *has_path) {
    const char *p = strstr(url, "://");
    *https = (strncmp(url, "https://", 8) == 0);
    p = p ? p + 3 : url;
    size_t n = strcspn(p, "/:?#");
    *has_path = p[n] == '/' && p[n + 1] != '\0';
    if (n >= cap) n = cap - 1;
    memcpy(host, p, n);
    host[n] = '\0';
}

int main(int argc, char **argv) {
    const char *hostname = "microlink-p3-probe";
    const char *ctrl_host = NULL;
    int followup_wait = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--hostname") && i + 1 < argc) hostname = argv[++i];
        else if (!strcmp(argv[i], "--ctrl-host") && i + 1 < argc) ctrl_host = argv[++i];
        else if (!strcmp(argv[i], "--followup-wait") && i + 1 < argc) followup_wait = atoi(argv[++i]);
        else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 1; }
    }

    microlink_t *ml = calloc(1, sizeof(*ml));
    if (!ml) return 1;
    ml->coord_sock = -1;
    ml->interactive = true;                       /* no auth key: the case under test */
    ml->config.auth_key = NULL;
    ml->config.device_name = hostname;
    ml->t_ctrl_watchdog_ms = ML_CTRL_WATCHDOG_MS;
    if (ctrl_host) snprintf(ml->ctrl_host, sizeof(ml->ctrl_host), "%s", ctrl_host);
    gen_keypair(ml->machine_private_key, ml->machine_public_key);
    gen_keypair(ml->wg_private_key, ml->wg_public_key);
    gen_keypair(ml->disco_private_key, ml->disco_public_key);
    say("keys: fresh machine, node and disco keys generated in memory (not stored)");
    say("config: auth_key=none, control host %s", CTRL_HOST(ml));

    ml_noise_state_t noise = {0};
    int rc = 1;

    if (do_tcp_connect(ml) < 0)            { say("FAIL transport: tcp connect"); goto out; }
    say("transport: tcp connected to control port 80");
    if (do_noise_handshake(ml, &noise) < 0) { say("FAIL transport: noise handshake"); goto out; }
    process_proactive_frames(ml, &noise);
    say("transport: noise handshake complete, node key challenge %s",
        s_has_node_key_challenge ? "received" : "absent");
    if (do_h2_preface(ml, &noise) < 0)      { say("FAIL transport: h2 preface"); goto out; }
    say("transport: h2 preface exchanged");

    reg_params_t rp = {
        .stream_id = 1,
        .node_priv = ml->wg_private_key,
        .node_pub = ml->wg_public_key,
        .old_node_pub = NULL,
        .followup = NULL,
    };
    ml_register_result_t rr;
    microlink_error_t err = ML_ERR_NONE;
    if (register_exchange(ml, &noise, &rp, &rr, &err) < 0) {
        say("FAIL transport: register exchange (error category %d)", (int)err);
        goto out;
    }

    cJSON *req = g_last_request ? cJSON_Parse(g_last_request) : NULL;
    char req_shape[256];
    shape(req, req_shape, sizeof(req_shape));
    say("request: %zu bytes, fields {%s}", g_last_request ? strlen(g_last_request) : 0, req_shape);
    cJSON_Delete(req);

    static const char *const kind_name[] = {"OK", "AUTH_URL", "NODE_KEY_EXPIRED", "REJECTED",
                                            "TAILNET_LOCK", "EMPTY", "MALFORMED"};
    say("response: kind=%s node_key_expired=%d machine_authorized=%d error_present=%d",
        kind_name[rr.kind], rr.node_key_expired, rr.machine_authorized, rr.error_present);

    if (rr.kind != ML_REG_AUTH_URL) {
        say("RESULT: no AuthURL (keyless register answered with kind %s)", kind_name[rr.kind]);
        ml_register_result_clear(&rr);
        rc = 2;
        goto out;
    }

    char host[96];
    bool https, has_path;
    url_host(rr.auth_url, host, sizeof(host), &https, &has_path);
    say("RESULT: AuthURL received, length %zu, host %s, scheme %s, path %s",
        strlen(rr.auth_url), host, https ? "https" : "other", has_path ? "present" : "empty");
    rc = 0;

    if (followup_wait > 0) {
        ml_set_auth_url(ml, rr.auth_url);
        reg_stream_t rs;
        if (followup_open(ml, &noise, &rs, 3) < 0) {
            say("FAIL transport: followup request could not be sent");
            rc = 1;
        } else {
            say("followup: request sent on stream 3 (Followup = the AuthURL), holding for %d s", followup_wait);
            uint64_t t0 = ml_get_time_ms(), last_ping = t0;
            int pr = 0;
            microlink_error_t ferr = ML_ERR_NONE;
            while (ml_get_time_ms() - t0 < (uint64_t)followup_wait * 1000u) {
                uint64_t now = ml_get_time_ms();
                if (now - last_ping >= ML_H2_PING_INTERVAL_MS) {
                    send_h2_ping(ml, &noise, now);
                    last_ping = now;
                }
                pr = register_poll(ml, &noise, &rs, &ferr);
                if (pr < 0 || pr == 2) break;
            }
            if (pr == 2) {
                ml_register_result_t fr;
                ml_register_parse_response(rs.body, rs.body_len, &fr);
                say("followup: answered early, kind=%s", kind_name[fr.kind]);
                ml_register_result_clear(&fr);
                rc = 2;
            } else if (pr < 0) {
                say("followup: connection failed (category %d)", (int)ferr);
                rc = 1;
            } else {
                say("followup: still pending after %d s (the server holds it until the login is finished)",
                    followup_wait);
            }
            reg_stream_free(&rs);
        }
    }
    ml_register_result_clear(&rr);
    say("end: connection dropped, nothing stored, no login completed");

out:
    if (ml->coord_sock >= 0) close(ml->coord_sock);
    ml_set_auth_url(ml, NULL);
    memset(ml->machine_private_key, 0, 32);
    memset(ml->wg_private_key, 0, 32);
    free(g_last_request);
    free(ml);
    return rc;
}
