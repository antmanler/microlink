/**
 * Tests of the coord task's decision code, run on the host.
 *
 * ml_coord.c is #included, so these call the firmware's own static functions:
 * the command handler, the key-expiry handler, the login entry, the receive
 * helpers, poll_map_update() and do_fetch_peers(). The control connection is a
 * socketpair; the "server" end sends real Noise-encrypted HTTP/2 frames.
 *
 * Bodies below are fabricated placeholders: no real URL, key or login name.
 */

#include "microlink_internal.h"
#include "ml_register.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "ml_coord.c"

extern int stub_rotate_calls, stub_clear_calls;
extern esp_err_t stub_rotate_result;

static int g_failed, g_total;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_total++;                                                           \
        if (!(cond)) {                                                       \
            g_failed++;                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* ---- fixtures ------------------------------------------------------------- */

static microlink_state_t g_cb_states[8];
static int g_cb_count;

static void on_state(microlink_t *ml, microlink_state_t st, void *user) {
    (void)ml; (void)user;
    if (g_cb_count < 8) g_cb_states[g_cb_count++] = st;
}

extern EventBits_t shim_event_bits_set, shim_event_bits_get;

static microlink_t *new_ml(bool interactive) {
    microlink_t *ml = calloc(1, sizeof(*ml));
    portMUX_INITIALIZE(&ml->id_lock);
    ml->coord_sock = -1;
    ml->interactive = interactive;
    ml->config.device_name = "dev-1";
    ml->state_cb = on_state;
    g_cb_count = 0;
    return ml;
}

/* A control connection whose far end this test drives. */
typedef struct {
    int srv_fd;
    uint8_t key[32];     /* server->client transport key */
    uint64_t nonce;      /* next server->client nonce */
} fake_conn_t;

static void conn_open(microlink_t *ml, ml_noise_state_t *noise, fake_conn_t *c) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    ml->coord_sock = sv[0];
    c->srv_fd = sv[1];
    memset(c->key, 0x5A, sizeof(c->key));
    c->nonce = 0;
    memset(noise, 0, sizeof(*noise));
    memcpy(noise->rx_key, c->key, sizeof(c->key));
}

static void conn_close(microlink_t *ml, fake_conn_t *c) {
    if (ml->coord_sock >= 0) { close(ml->coord_sock); ml->coord_sock = -1; }
    if (c->srv_fd >= 0) { close(c->srv_fd); c->srv_fd = -1; }
}

static void write_all(int fd, const uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) { perror("write"); exit(2); }
        p += w; n -= (size_t)w;
    }
}

/* One server->client Noise transport frame. */
static void srv_noise_frame(fake_conn_t *c, const uint8_t *pt, size_t len) {
    uint8_t *buf = malloc(3 + len + 16);
    buf[0] = 0x04;
    buf[1] = (uint8_t)((len + 16) >> 8);
    buf[2] = (uint8_t)((len + 16) & 0xFF);
    ml_noise_encrypt(c->key, c->nonce++, NULL, 0, pt, len, buf + 3);
    write_all(c->srv_fd, buf, 3 + len + 16);
    free(buf);
}

/* An H2 frame header plus `have` payload bytes; `declared` may exceed `have` (a frame cut by
 * the Noise frame boundary). Returns the bytes written to out. */
static size_t h2_frame(uint8_t *out, uint8_t type, uint8_t flags, uint32_t stream,
                       const uint8_t *payload, size_t have, size_t declared) {
    out[0] = (uint8_t)(declared >> 16); out[1] = (uint8_t)(declared >> 8); out[2] = (uint8_t)declared;
    out[3] = type; out[4] = flags;
    out[5] = (uint8_t)(stream >> 24); out[6] = (uint8_t)(stream >> 16);
    out[7] = (uint8_t)(stream >> 8);  out[8] = (uint8_t)stream;
    memcpy(out + 9, payload, have);
    return 9 + have;
}

static void srv_data(fake_conn_t *c, uint32_t stream, uint8_t flags, const char *json,
                     size_t declared_len) {
    uint8_t buf[8192];
    size_t have = strlen(json);
    size_t n = h2_frame(buf, 0x00, flags, stream, (const uint8_t *)json, have,
                        declared_len ? declared_len : have);
    srv_noise_frame(c, buf, n);
}

static void drain(int fd) {                    /* what the client wrote is not under test */
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    uint8_t scratch[4096];
    while (read(fd, scratch, sizeof(scratch)) > 0) {}
    fcntl(fd, F_SETFL, fl);
}

/* ---- M1: commands --------------------------------------------------------- */

static void test_commands(void) {
    microlink_t *ml = new_ml(true);
    coord_state_t st;

    /* FORCE_RECONNECT (microlink_rebind, DERP failure) never leaves a terminal error. */
    st = COORD_FAILED; ml->state = ML_STATE_ERROR; ml->last_error = ML_ERR_TAILNET_LOCK;
    coord_handle_command(ml, &st, ML_CMD_FORCE_RECONNECT);
    CHECK(st == COORD_FAILED);
    CHECK(ml->state == ML_STATE_ERROR && ml->last_error == ML_ERR_TAILNET_LOCK);

    /* RETRY (microlink_retry) does, and clears the category. */
    coord_handle_command(ml, &st, ML_CMD_RETRY);
    CHECK(st == COORD_RECONNECTING);
    CHECK(ml->last_error == ML_ERR_NONE);

    /* RETRY outside FAILED is ignored. */
    st = COORD_LONG_POLL; ml->last_error = ML_ERR_NETWORK;
    coord_handle_command(ml, &st, ML_CMD_RETRY);
    CHECK(st == COORD_LONG_POLL && ml->last_error == ML_ERR_NETWORK);
    st = COORD_LOGIN_WAIT;
    coord_handle_command(ml, &st, ML_CMD_RETRY);
    CHECK(st == COORD_LOGIN_WAIT);

    /* Elsewhere FORCE_RECONNECT behaves as before. */
    st = COORD_LONG_POLL;
    coord_handle_command(ml, &st, ML_CMD_FORCE_RECONNECT);
    CHECK(st == COORD_RECONNECTING);
    st = COORD_LOGIN_WAIT;
    coord_handle_command(ml, &st, ML_CMD_FORCE_RECONNECT);
    CHECK(st == COORD_RECONNECTING);

    /* CONNECT only starts an idle task. */
    st = COORD_IDLE;
    coord_handle_command(ml, &st, ML_CMD_CONNECT);
    CHECK(st == COORD_STUN_PROBE && ml->state == ML_STATE_CONNECTING);
    st = COORD_FAILED; ml->state = ML_STATE_ERROR;
    coord_handle_command(ml, &st, ML_CMD_CONNECT);
    CHECK(st == COORD_FAILED && ml->state == ML_STATE_ERROR);

    /* DISCONNECT closes the control socket and goes idle, from any state. */
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    ml->coord_sock = sv[0];
    st = COORD_LOGIN_WAIT;
    coord_handle_command(ml, &st, ML_CMD_DISCONNECT);
    CHECK(st == COORD_IDLE && ml->state == ML_STATE_IDLE && ml->coord_sock == -1);
    CHECK(write(sv[0], "x", 1) < 0);                  /* really closed */
    close(sv[1]);
    free(ml);
}

/* ---- M2: key expiry ------------------------------------------------------- */

static void test_key_expired(void) {
    microlink_t *ml = new_ml(true);
    ml_noise_state_t noise;
    coord_state_t st = COORD_REGISTER;
    memset(&noise, 0xEE, sizeof(noise));

    /* A stale OLD_PUB left by an earlier rotation whose clear failed must not make this
     * first expiry terminal: the rotation runs and overwrites it. */
    memset(ml->wg_public_key, 0x33, 32);
    memset(ml->old_node_pub, 0x44, 32);
    ml->old_node_valid = true;
    stub_rotate_calls = 0;
    stub_rotate_result = ESP_OK;

    coord_handle_key_expired(ml, &noise, &st);
    CHECK(stub_rotate_calls == 1);
    CHECK(st == COORD_FAILED && ml->state == ML_STATE_ERROR && ml->last_error == ML_ERR_KEY_ROTATED);
    CHECK(ml->rotated_this_session);
    CHECK(ml->old_node_valid && ml->old_node_pub[0] == 0x33);        /* the expired key is the old key now */
    CHECK(g_cb_count == 1 && g_cb_states[0] == ML_STATE_ERROR);
    CHECK(noise.rx_key[0] == 0);                                     /* connection state wiped */

    /* A second expiry in the same session is terminal and rotates nothing. */
    st = COORD_REGISTER; ml->state = ML_STATE_REGISTERING; ml->last_error = ML_ERR_NONE;
    coord_handle_key_expired(ml, &noise, &st);
    CHECK(stub_rotate_calls == 1);
    CHECK(st == COORD_FAILED && ml->last_error == ML_ERR_NODE_KEY_EXPIRED);
    free(ml);

    /* A clean session rotates on its first expiry even with no OldNodeKey around. */
    ml = new_ml(false);
    stub_rotate_calls = 0;
    st = COORD_REGISTER;
    coord_handle_key_expired(ml, &noise, &st);                       /* auth-key callers rotate too */
    CHECK(stub_rotate_calls == 1 && ml->last_error == ML_ERR_KEY_ROTATED && st == COORD_FAILED);
    free(ml);

    /* NVS failure: STORAGE, and the next attempt may still rotate. */
    ml = new_ml(true);
    stub_rotate_calls = 0;
    stub_rotate_result = ESP_FAIL;
    st = COORD_REGISTER;
    coord_handle_key_expired(ml, &noise, &st);
    CHECK(stub_rotate_calls == 1 && ml->last_error == ML_ERR_STORAGE && st == COORD_FAILED);
    CHECK(!ml->rotated_this_session);
    stub_rotate_result = ESP_OK;
    st = COORD_REGISTER;
    coord_handle_key_expired(ml, &noise, &st);
    CHECK(stub_rotate_calls == 2 && ml->last_error == ML_ERR_KEY_ROTATED);
    free(ml);
}

/* ---- L1: login entry ------------------------------------------------------ */

static void test_begin_login(void) {
    ml_noise_state_t noise;
    memset(&noise, 0, sizeof(noise));
    coord_state_t st = COORD_REGISTER;

    microlink_t *ml = new_ml(true);
    CHECK(coord_begin_login(ml, &noise, &st, "https://example.invalid/a/placeholder"));
    CHECK(st == COORD_LOGIN_WAIT && ml->state == ML_STATE_NEEDS_LOGIN && ml->last_error == ML_ERR_NONE);
    CHECK(g_cb_count == 1 && g_cb_states[0] == ML_STATE_NEEDS_LOGIN);
    char buf[64];
    CHECK(microlink_copy_auth_url(ml, buf, sizeof(buf)) == ESP_OK);
    free(ml->auth_url);
    free(ml);

    /* An auth-key caller must not enter NEEDS_LOGIN: its key was not accepted. */
    ml = new_ml(false);
    st = COORD_REGISTER;
    CHECK(!coord_begin_login(ml, &noise, &st, "https://example.invalid/a/placeholder"));
    CHECK(st == COORD_FAILED && ml->state == ML_STATE_ERROR && ml->last_error == ML_ERR_REGISTER_REJECTED);
    CHECK(g_cb_count == 1 && g_cb_states[0] == ML_STATE_ERROR);
    CHECK(ml->auth_url == NULL);
    CHECK(microlink_copy_auth_url(ml, buf, sizeof(buf)) == ESP_ERR_NOT_FOUND);
    free(ml);
}

/* ---- L5: receive results -------------------------------------------------- */

static void test_recv_results(void) {
    microlink_t *ml = new_ml(true);
    ml_noise_state_t noise;
    fake_conn_t c;
    uint8_t pt[256];
    int fl;

    /* Nothing pending, stream aligned: IDLE. */
    conn_open(ml, &noise, &c);
    fl = fcntl(ml->coord_sock, F_GETFL);
    fcntl(ml->coord_sock, F_SETFL, fl | O_NONBLOCK);
    CHECK(noise_recv(ml, &noise, pt, sizeof(pt)) == COORD_RECV_IDLE);

    /* A good frame still decrypts. */
    const uint8_t hello[] = "hello";
    srv_noise_frame(&c, hello, sizeof(hello));
    CHECK(noise_recv(ml, &noise, pt, sizeof(pt)) == (int)sizeof(hello) && !memcmp(pt, hello, sizeof(hello)));

    /* A bad frame type is fatal even when errno holds a stale EAGAIN. */
    const uint8_t junk[] = {0x99, 0x00, 0x20, 0, 0, 0, 0, 0};
    write_all(c.srv_fd, junk, sizeof(junk));
    errno = EAGAIN;
    CHECK(noise_recv(ml, &noise, pt, sizeof(pt)) == COORD_RECV_FATAL);
    conn_close(ml, &c);

    /* A tampered ciphertext (decrypt failure) is fatal. */
    conn_open(ml, &noise, &c);
    uint8_t bad[3 + 5 + 16] = {0x04, 0x00, 5 + 16};
    write_all(c.srv_fd, bad, sizeof(bad));
    errno = EAGAIN;
    CHECK(noise_recv(ml, &noise, pt, sizeof(pt)) == COORD_RECV_FATAL);
    conn_close(ml, &c);

    /* The peer closed: fatal, not idle, whatever errno held. */
    conn_open(ml, &noise, &c);
    close(c.srv_fd); c.srv_fd = -1;
    errno = EAGAIN;
    CHECK(noise_recv(ml, &noise, pt, sizeof(pt)) == COORD_RECV_FATAL);
    conn_close(ml, &c);

    /* Consumed bytes and then silence leave the stream misaligned: fatal (about 3 s, the
     * existing partial-read retry budget). */
    conn_open(ml, &noise, &c);
    fl = fcntl(ml->coord_sock, F_GETFL);
    fcntl(ml->coord_sock, F_SETFL, fl | O_NONBLOCK);
    const uint8_t one = 0x04;
    write_all(c.srv_fd, &one, 1);
    CHECK(noise_recv(ml, &noise, pt, sizeof(pt)) == COORD_RECV_FATAL);
    conn_close(ml, &c);

    /* The callers decide on the code, not on errno. */
    fake_conn_t c2;
    conn_open(ml, &noise, &c2);
    write_all(c2.srv_fd, junk, sizeof(junk));
    errno = EAGAIN;
    CHECK(poll_map_update(ml, &noise, NULL) == -1);                    /* fatal, not "no data" */
    conn_close(ml, &c2);

    reg_stream_t rs;
    microlink_error_t err = ML_ERR_NONE;
    conn_open(ml, &noise, &c2);
    CHECK(reg_stream_init(&rs, 3));
    write_all(c2.srv_fd, junk, sizeof(junk));
    errno = EAGAIN;
    CHECK(register_poll(ml, &noise, &rs, &err) == -1 && err == ML_ERR_NETWORK);
    reg_stream_free(&rs);
    conn_close(ml, &c2);

    conn_open(ml, &noise, &c2);                                         /* quiet line: 0, not an error */
    CHECK(reg_stream_init(&rs, 3));
    err = ML_ERR_NONE;
    CHECK(register_poll(ml, &noise, &rs, &err) == 0 && err == ML_ERR_NONE);
    reg_stream_free(&rs);
    CHECK(poll_map_update(ml, &noise, NULL) == 0);
    conn_close(ml, &c2);
    free(ml);
}

/* ---- H1: poll_map_update reports a netmap update it could not read -------- */

static void test_poll_map_update(void) {
    microlink_t *ml = new_ml(true);
    ml_noise_state_t noise;
    fake_conn_t c;
    bool unparsed;

    /* The approval, small and complete: read and applied. */
    conn_open(ml, &noise, &c);
    srv_data(&c, 5, 0, "{\"Node\":{\"Name\":\"dev-1.tail1234.ts.net.\",\"MachineAuthorized\":true}}", 0);
    unparsed = false;
    CHECK(poll_map_update(ml, &noise, &unparsed) == 1);
    CHECK(ml->machine_authorized && ml->machine_auth_known && !unparsed);
    char name[64];
    CHECK(microlink_copy_self_fqdn(ml, name, sizeof(name)) == ESP_OK && !strcmp(name, "dev-1.tail1234.ts.net"));
    drain(c.srv_fd);
    conn_close(ml, &c);

    /* An update with no self node: nothing to apply, nothing lost. */
    conn_open(ml, &noise, &c);
    ml->machine_authorized = false;
    srv_data(&c, 5, 0, "{\"PeersRemoved\":[]}", 0);
    unparsed = false;
    CHECK(poll_map_update(ml, &noise, &unparsed) == 1 && !unparsed && !ml->machine_authorized);
    drain(c.srv_fd);
    conn_close(ml, &c);

    /* A big update: the DATA frame is cut by the Noise frame boundary (this call reads one
     * Noise frame). The approval inside it is lost, so the caller must be told. */
    conn_open(ml, &noise, &c);
    srv_data(&c, 5, 0, "{\"Node\":{\"MachineAuthorized\":tr", 6000);
    unparsed = false;
    CHECK(poll_map_update(ml, &noise, &unparsed) == 1);
    CHECK(unparsed);
    CHECK(!ml->machine_authorized);
    drain(c.srv_fd);
    conn_close(ml, &c);

    /* Stream-5 JSON that does not parse. */
    conn_open(ml, &noise, &c);
    srv_data(&c, 5, 0, "{\"Node\":{", 0);
    unparsed = false;
    CHECK(poll_map_update(ml, &noise, &unparsed) == 1 && unparsed);
    drain(c.srv_fd);
    conn_close(ml, &c);

    /* Keepalive-style traffic (PING) is not a lost update. */
    conn_open(ml, &noise, &c);
    uint8_t ping[17], payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t n = h2_frame(ping, 0x06, 0x00, 0, payload, 8, 8);
    srv_noise_frame(&c, ping, n);
    unparsed = false;
    CHECK(poll_map_update(ml, &noise, &unparsed) == 1 && !unparsed);
    drain(c.srv_fd);
    conn_close(ml, &c);

    /* The out-parameter is optional. */
    conn_open(ml, &noise, &c);
    srv_data(&c, 5, 0, "{\"Node\":{\"MachineAuthorized\":tr", 6000);
    CHECK(poll_map_update(ml, &noise, NULL) == 1);
    drain(c.srv_fd);
    conn_close(ml, &c);
    free(ml);
}

/* ---- L6: a full netmap without the self node ------------------------------ */

static int fetch_with(microlink_t *ml, const char *map_json) {
    ml_noise_state_t noise;
    fake_conn_t c;
    conn_open(ml, &noise, &c);
    srv_data(&c, 3, 0x01 /* END_STREAM */, map_json, 0);
    int r = do_fetch_peers(ml, &noise);
    drain(c.srv_fd);
    conn_close(ml, &c);
    return r;
}

static void test_fetch_self_node(void) {
    /* Interactive: a netmap without the self node is a protocol error, never CONNECTED. */
    microlink_t *ml = new_ml(true);
    CHECK(fetch_with(ml, "{\"Peers\":[]}") == -1);
    CHECK(ml->last_error == ML_ERR_PROTOCOL);
    CHECK(!ml->machine_auth_known);
    free(ml);

    /* Interactive with a self node: read; absence of MachineAuthorized means "not approved". */
    ml = new_ml(true);
    CHECK(fetch_with(ml, "{\"Node\":{\"Name\":\"dev-1.tail1234.ts.net.\"},\"Peers\":[]}") == 0);
    CHECK(ml->machine_auth_known && !ml->machine_authorized && ml->last_error == ML_ERR_NONE);
    char name[64];
    CHECK(microlink_copy_magicdns_suffix(ml, name, sizeof(name)) == ESP_OK && !strcmp(name, "tail1234.ts.net"));
    free(ml);

    ml = new_ml(true);
    CHECK(fetch_with(ml, "{\"Node\":{\"Name\":\"dev-1.tail1234.ts.net.\",\"MachineAuthorized\":true,"
                         "\"Addresses\":[\"100.64.0.5/32\"]},\"Peers\":[]}") == 0);
    CHECK(ml->machine_auth_known && ml->machine_authorized && ml->vpn_ip == 0x64400005u);
    free(ml);

    /* Auth-key callers keep the old tolerance. */
    ml = new_ml(false);
    CHECK(fetch_with(ml, "{\"Peers\":[]}") == 0);
    CHECK(ml->last_error == ML_ERR_NONE && !ml->machine_auth_known);
    free(ml);
}

/* ---- A: DERP home region by measured latency (ml_netcheck.c) -------------- */

extern int stub_binding_sent;
extern uint32_t stub_binding_ip[256];
extern uint8_t stub_binding_txid[256][12];

/* Regions 901, 902, 904 only (no region 9). 904 is Avoid, 905 NoMeasureNoHome, 906 has
 * STUN disabled. Addresses are documentation ranges, host names placeholders. */
#define NC_MAP                                                                              \
    "\"DERPMap\":{\"Regions\":{"                                                             \
    "\"901\":{\"RegionID\":901,\"RegionCode\":\"r1\",\"Nodes\":["                           \
    "{\"HostName\":\"d1a.example.invalid\",\"IPv4\":\"192.0.2.1\"},"                        \
    "{\"HostName\":\"d1b.example.invalid\",\"IPv4\":\"192.0.2.2\",\"STUNPort\":3479}]},"    \
    "\"902\":{\"RegionID\":902,\"RegionCode\":\"r2\",\"Nodes\":["                           \
    "{\"HostName\":\"d2.example.invalid\",\"IPv4\":\"198.51.100.1\"}]},"                    \
    "\"904\":{\"RegionID\":904,\"RegionCode\":\"r4\",\"Avoid\":true,\"Nodes\":["            \
    "{\"HostName\":\"d4.example.invalid\",\"IPv4\":\"203.0.113.1\"}]},"                     \
    "\"905\":{\"RegionID\":905,\"RegionCode\":\"r5\",\"NoMeasureNoHome\":true,\"Nodes\":[" \
    "{\"HostName\":\"d5.example.invalid\",\"IPv4\":\"203.0.113.2\"}]},"                     \
    "\"906\":{\"RegionID\":906,\"RegionCode\":\"r6\",\"Nodes\":["                           \
    "{\"HostName\":\"d6.example.invalid\",\"IPv4\":\"203.0.113.3\",\"STUNPort\":-1}]}}}"

static int region_idx(microlink_t *ml, uint16_t id) {
    for (int i = 0; i < ml->derp_region_count; i++)
        if (ml->derp_regions[i].region_id == id) return i;
    return -1;
}

/* Answer the probe sent to `ip` (the first one, or the try-th) after rtt_us. */
static bool nc_reply(microlink_t *ml, int first_probe, uint32_t ip, int64_t sent_us, int64_t rtt_us) {
    for (int i = first_probe; i < stub_binding_sent; i++) {
        if (stub_binding_ip[i] != ip) continue;
        uint8_t r[20] = {0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
        memcpy(r + 8, stub_binding_txid[i], 12);
        (void)sent_us;
        return ml_netcheck_on_stun(ml, r, sizeof(r), sent_us + rtt_us);
    }
    return false;
}

/* Run one round: begin at t0, send the first wave, answer given regions. */
static void nc_round(microlink_t *ml, int64_t t0, uint32_t ip_a, int64_t rtt_a,
                     uint32_t ip_b, int64_t rtt_b) {
    int first = stub_binding_sent;
    CHECK(ml_netcheck_begin(ml, t0));
    CHECK(ml_netcheck_service(ml, t0) >= 0);
    if (ip_a) CHECK(nc_reply(ml, first, ip_a, t0, rtt_a));
    if (ip_b) CHECK(nc_reply(ml, first, ip_b, t0, rtt_b));
}

static void test_netcheck_plan(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    CHECK(ml->derp_region_count == 5);
    int i904 = region_idx(ml, 904), i905 = region_idx(ml, 905), i906 = region_idx(ml, 906);
    CHECK(ml->derp_regions[i904].avoid && ml->derp_regions[i905].no_measure);
    CHECK(ml->derp_regions[i906].nodes[0].stun_port == -1);

    /* No region 9 in the map: the home region is the first one, never 9. */
    CHECK(ml->derp_home_region == 901);
    CHECK(ml_netcheck_due(ml, 1000));

    /* Initial plan: 901 and 902 only, three tries 100 ms apart, nodes in turn. */
    for (int r = 0; r < ml->derp_region_count; r++)
        for (int n = 0; n < ml->derp_regions[r].node_count; n++) {
            ml_derp_node_t *nd = &ml->derp_regions[r].nodes[n];
            unsigned a, b, c, d;
            if (sscanf(nd->ipv4, "%u.%u.%u.%u", &a, &b, &c, &d) == 4)
                nd->stun_ipv4 = (a << 24) | (b << 16) | (c << 8) | d;
        }
    ml_nc_probe_t plan[ML_NC_MAX_PROBES];
    int n = ml_nc_make_plan(ml->derp_regions, ml->derp_region_count, NULL, 0, 901, plan, ML_NC_MAX_PROBES);
    CHECK(n == 6);
    int i901 = region_idx(ml, 901), i902 = region_idx(ml, 902);
    CHECK(plan[0].region == i901 && plan[0].node == 0 && plan[0].delay_us == 0);
    CHECK(plan[1].region == i901 && plan[1].node == 1 && plan[1].delay_us == 100000);
    CHECK(plan[2].region == i901 && plan[2].node == 0 && plan[2].delay_us == 200000);
    CHECK(plan[3].region == i902 && plan[5].delay_us == 200000);

    /* Incremental plan: fastest first; home gets four tries spaced by its latency. */
    ml_nc_sample_t last[2] = {{902, 20000}, {901, 50000}};
    n = ml_nc_make_plan(ml->derp_regions, ml->derp_region_count, last, 2, 901, plan, ML_NC_MAX_PROBES);
    CHECK(n == 2 + 4);
    CHECK(plan[0].region == i902 && plan[1].delay_us == 24000);                 /* 20 ms * 1.2 */
    CHECK(plan[2].region == i901 && plan[3].delay_us == 60000);
    CHECK(plan[4].delay_us == 2 * 60000 + 2 * 50000 && plan[5].delay_us == 3 * 60000 + 3 * 50000);
    free(ml);
}

static void test_netcheck_choice(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    const uint32_t ip901 = 0xC0000201u, ip902 = 0xC6336401u;   /* 192.0.2.1, 198.51.100.1 */
    int64_t t = 1000000000;

    /* 902 at 20 ms against 901 at 80 ms: home moves to 902. Avoid / NoMeasure / no-STUN
     * regions are never probed. */
    int first = stub_binding_sent;
    nc_round(ml, t, ip901, 80000, ip902, 20000);
    for (int i = first; i < stub_binding_sent; i++)
        CHECK(stub_binding_ip[i] == ip901 || stub_binding_ip[i] == ip902);
    CHECK(ml_netcheck_service(ml, t + 1000) == -1);         /* every region replied */
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);
    CHECK(ml->netcheck.last_count == 2 && ml->netcheck.probes != NULL && !ml->netcheck.open);
    CHECK(!ml_netcheck_due(ml, (uint64_t)(t / 1000) + 1000));
    CHECK(ml_netcheck_due(ml, (uint64_t)(t / 1000) + 23000));

    /* Hysteresis: 901 at 15 ms is under 2/3 of 902's 24 ms but only 9 ms better
     * (under 10 ms): stay. */
    t += 30000000;
    nc_round(ml, t, ip901, 15000, ip902, 24000);
    CHECK(!ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);

    /* 901 at 70 ms vs 902 at 100 ms: 30 ms better but not under 2/3 of 100 ms: stay. */
    t += 30000000;
    nc_round(ml, t, ip901, 70000, ip902, 100000);
    CHECK(!ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);

    /* 901 at 60 ms vs 902 at 100 ms: clearly better: move. */
    t += 30000000;
    nc_round(ml, t, ip901, 60000, ip902, 100000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 901);

    /* No region answers: the round times out and the previous home stays. */
    t += 30000000;
    nc_round(ml, t, 0, 0, 0, 0);
    CHECK(ml_netcheck_service(ml, t + 100000) > 0);         /* still waiting, next try due */
    CHECK(ml_netcheck_service(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL) == -1);
    CHECK(!ml_netcheck_end(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL) && ml->derp_home_region == 901);
    CHECK(ml->netcheck.last_count == 0);

    /* A reply nobody asked for is not a latency sample. */
    uint8_t stray[20] = {0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
    CHECK(ml_netcheck_begin(ml, t));
    CHECK(!ml_netcheck_on_stun(ml, stray, sizeof(stray), t + 1000));
    ml_netcheck_end(ml, t + 1000);
    free(ml);

    /* No previous home and no reply: the first region of the map that can be home. */
    ml = new_ml(false);
    CHECK(fetch_with(ml, "{\"DERPMap\":{\"Regions\":{"
                         "\"904\":{\"RegionID\":904,\"Avoid\":true,\"Nodes\":[{\"HostName\":\"a.example.invalid\",\"IPv4\":\"203.0.113.1\"}]},"
                         "\"907\":{\"RegionID\":907,\"Nodes\":[{\"HostName\":\"b.example.invalid\",\"IPv4\":\"203.0.113.7\"}]}}},"
                         "\"Peers\":[]}") == 0);
    CHECK(ml->derp_home_region == 907);
    t = 2000000000;
    nc_round(ml, t, 0, 0, 0, 0);
    /* The map set the home region (none before): reported once so DERP connects there. */
    CHECK(ml_netcheck_end(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL) && ml->derp_home_region == 907);
    free(ml);

    /* Pure choice: an Avoid region never wins even when fastest; a silent old home
     * still heard on DERP is kept. */
    ml_derp_region_t regs[3];
    memset(regs, 0, sizeof(regs));
    regs[0].region_id = 901; regs[0].node_count = 1; strcpy(regs[0].nodes[0].hostname, "x");
    regs[1].region_id = 902; regs[1].node_count = 1; strcpy(regs[1].nodes[0].hostname, "y");
    regs[2].region_id = 904; regs[2].node_count = 1; strcpy(regs[2].nodes[0].hostname, "z");
    regs[2].avoid = true;
    uint32_t lat[3] = {50000, 0, 1000};
    CHECK(ml_nc_pick_home(regs, 3, lat, 0, false) == 901);
    CHECK(ml_nc_pick_home(regs, 3, lat, 902, true) == 902);
    CHECK(ml_nc_pick_home(regs, 3, lat, 902, false) == 901);
    CHECK(ml_nc_pick_home(regs, 3, lat, 9, false) == 901);   /* 9 is not in the map */
    uint32_t none[3] = {0, 0, 0};
    CHECK(ml_nc_pick_home(regs, 3, none, 9, false) == 901);
}

/* ---- C: priority peer by name ----------------------------------------------- */

extern void *stub_cmd_queue;
extern int stub_cmd_sent, stub_cmd_last;

static void test_priority_name_match(void) {
    CHECK(ml_dns_name_equal("P4-Dock.Tail1234.TS.net.", "p4-dock.tail1234.ts.net"));
    CHECK(ml_dns_name_equal("p4-dock.tail1234.ts.net", "p4-dock.tail1234.ts.net."));
    CHECK(!ml_dns_name_equal("p4-dock.tail1234.ts.net", "p4-dock2.tail1234.ts.net"));
    CHECK(!ml_dns_name_equal("p4-dock", "p4-dock.tail1234.ts.net"));
    CHECK(!ml_dns_name_equal("", ""));
    CHECK(!ml_dns_name_equal(NULL, "a"));
}

static void test_priority_setter(void) {
    microlink_t *ml = new_ml(false);
    int cmdq;
    ml->coord_cmd_queue = &cmdq;
    stub_cmd_queue = &cmdq;
    stub_cmd_sent = 0;

    /* Before start: stored, nothing queued. */
    ml->state = ML_STATE_IDLE;
    CHECK(microlink_set_priority_peer_name(ml, "p4-dock.tail1234.ts.net.") == ESP_OK);
    CHECK(!strcmp(ml->priority_name, "p4-dock.tail1234.ts.net") && stub_cmd_sent == 0);

    /* Connected: the same name (any case) changes nothing; a new one re-reads the netmap. */
    ml->state = ML_STATE_CONNECTED;
    CHECK(microlink_set_priority_peer_name(ml, "P4-DOCK.tail1234.ts.net") == ESP_OK && stub_cmd_sent == 0);
    CHECK(microlink_set_priority_peer_name(ml, "speaker.tail1234.ts.net") == ESP_OK);
    CHECK(stub_cmd_sent == 1 && stub_cmd_last == ML_CMD_RESYNC_NETMAP);

    /* Clearing never needs a re-read; bad arguments are refused. */
    CHECK(microlink_set_priority_peer_name(ml, NULL) == ESP_OK && ml->priority_name[0] == '\0');
    CHECK(stub_cmd_sent == 1 && (shim_event_bits_set & ML_EVT_PRIORITY_CLEARED));
    char longname[ML_DNS_NAME_MAX + 3];
    memset(longname, 'a', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    CHECK(microlink_set_priority_peer_name(ml, longname) == ESP_ERR_INVALID_ARG);
    CHECK(microlink_set_priority_peer_name(NULL, "x") == ESP_ERR_INVALID_ARG);

    /* The coord task reconnects to read the full netmap only from the long-poll. */
    coord_state_t st = COORD_LONG_POLL;
    coord_handle_command(ml, &st, ML_CMD_RESYNC_NETMAP);
    CHECK(st == COORD_RECONNECTING);
    st = COORD_FAILED;
    coord_handle_command(ml, &st, ML_CMD_RESYNC_NETMAP);
    CHECK(st == COORD_FAILED);
    stub_cmd_queue = NULL;
    free(ml);
}

/* The updates the last parse_netmap() queued, oldest first (what wg_mgr would take). */
static ml_peer_update_t *g_updates;
static int g_update_count;

static void free_updates(void) {
    while (g_updates) {
        ml_peer_update_t *next = g_updates->next;
        free(g_updates);
        g_updates = next;
    }
    g_update_count = 0;
}

static void parse_netmap(microlink_t *ml, const char *json) {
    free_updates();
    cJSON *root = cJSON_Parse(json);
    parse_peers_from_map_response(ml, root);
    cJSON_Delete(root);
    g_updates = ml_peer_updates_take_all(ml);
    for (const ml_peer_update_t *u = g_updates; u; u = u->next) g_update_count++;
}

static const ml_peer_update_t *update_at(int i) {
    const ml_peer_update_t *u = g_updates;
    while (u && i-- > 0) u = u->next;
    return u;
}

static void test_priority_marked_on_every_netmap(void) {
    microlink_t *ml = new_ml(false);
    ml_peer_updates_init(ml);
    const char *map = "{\"Peers\":["
        "{\"Name\":\"laptop.tail1234.ts.net.\",\"Addresses\":[\"100.64.0.2/32\"]},"
        "{\"Name\":\"P4-Dock.tail1234.ts.net.\",\"Addresses\":[\"100.64.0.3/32\"]},"
        "{\"Name\":\"p4-dock-2.tail1234.ts.net.\",\"Addresses\":[\"100.64.0.4/32\"]}]}";

    parse_netmap(ml, map);                                 /* no name set: none marked */
    CHECK(g_update_count == 3);
    for (int i = 0; i < 3; i++) CHECK(!update_at(i)->priority);

    microlink_set_priority_peer_name(ml, "p4-dock.tail1234.ts.net");
    parse_netmap(ml, map);
    CHECK(g_update_count == 3);
    CHECK(!update_at(0)->priority && update_at(1)->priority && !update_at(2)->priority);

    /* A changed name moves the mark on the next netmap. */
    microlink_set_priority_peer_name(ml, "laptop.tail1234.ts.net.");
    parse_netmap(ml, map);
    CHECK(update_at(0)->priority && !update_at(1)->priority);

    parse_netmap(ml, "{}");
    free_updates();
    ml_peer_updates_deinit(ml);
    free(ml);
}

/* A netmap lists every tailnet peer, and the coord task queues them all before wg_mgr
 * drains: far more than any fixed queue depth. Every update must arrive, in JSON order
 * across the three producers (Peers, PeersRemoved, PeersChangedPatch). */
static void node_key(char *out, size_t n, int i) {
    snprintf(out, n, "nodekey:%02x%02x%.60s", i & 255, (i >> 8) & 255,
             "abababababababababababababababababababababababababababababab");
}

static bool key_is(const ml_peer_update_t *u, int n) {
    return u->public_key[0] == (n & 255) && u->public_key[1] == ((n >> 8) & 255);
}

static void test_netmap_never_drops_updates(void) {
    enum { ADDS = 500, REMOVES = 100, PATCHES = 100 };
    size_t cap = 1 << 20, len = 0;
    char *json = malloc(cap);
    char key[80];
    len += snprintf(json + len, cap - len, "{\"Peers\":[");
    for (int i = 0; i < ADDS; i++) {
        node_key(key, sizeof(key), i);
        len += snprintf(json + len, cap - len,
                        "%s{\"Name\":\"peer-%d.tail1234.ts.net.\",\"Key\":\"%s\","
                        "\"Addresses\":[\"100.64.%d.%d/32\"]}",
                        i ? "," : "", i, key, (i >> 8) & 255, i & 255);
    }
    len += snprintf(json + len, cap - len, "],\"PeersRemoved\":[");
    for (int i = 0; i < REMOVES; i++) {
        node_key(key, sizeof(key), 1000 + i);
        len += snprintf(json + len, cap - len, "%s\"%s\"", i ? "," : "", key);
    }
    len += snprintf(json + len, cap - len, "],\"PeersChangedPatch\":{");
    for (int i = 0; i < PATCHES; i++) {
        node_key(key, sizeof(key), 2000 + i);
        len += snprintf(json + len, cap - len, "%s\"%s\":{\"DERPRegion\":%d}",
                        i ? "," : "", key, 1 + i);
    }
    len += snprintf(json + len, cap - len, "}}");
    CHECK(len < cap);

    microlink_t *ml = new_ml(false);
    ml_peer_updates_init(ml);
    parse_netmap(ml, json);
    CHECK(g_update_count == ADDS + REMOVES + PATCHES);

    const ml_peer_update_t *u = g_updates;
    bool in_order = g_update_count == ADDS + REMOVES + PATCHES;
    for (int i = 0; in_order && i < ADDS; i++, u = u->next) {
        in_order = u->action == ML_PEER_ADD && key_is(u, i) &&
                   u->vpn_ip == (0x64400000u | (uint32_t)i);
    }
    for (int i = 0; in_order && i < REMOVES; i++, u = u->next) {
        in_order = u->action == ML_PEER_REMOVE && key_is(u, 1000 + i);
    }
    for (int i = 0; in_order && i < PATCHES; i++, u = u->next) {
        in_order = u->action == ML_PEER_UPDATE_ENDPOINT && key_is(u, 2000 + i) &&
                   u->derp_region == 1 + i;
    }
    CHECK(in_order);

    /* The list is detached whole: nothing is left behind. */
    CHECK(ml_peer_updates_take_all(ml) == NULL);

    free_updates();
    ml_peer_updates_deinit(ml);
    free(json);
    free(ml);
}

static void test_priority_admission(void) {
    ml_peer_t peers[ML_MAX_PEERS];
    bool evict;
    memset(peers, 0, sizeof(peers));
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, false, &evict) == 0 && !evict);

    /* Full table of ordinary peers: an ordinary newcomer is refused (netmap order wins),
     * a priority one evicts the least recently active peer. */
    for (int i = 0; i < ML_MAX_PEERS; i++) {
        peers[i].active = true;
        peers[i].last_send_ms = 1000 + i * 10;
        peers[i].last_pong_recv_ms = 500;
    }
    peers[5].last_send_ms = 100;
    peers[5].last_pong_recv_ms = 3000;     /* recent pong: not the least active */
    peers[7].last_send_ms = 200;
    peers[7].last_pong_recv_ms = 150;
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, false, &evict) == -1 && !evict);
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, true, &evict) == 7 && evict);

    /* A priority peer is never the one evicted. */
    peers[7].priority = true;
    int v = ml_peer_admit_slot(peers, ML_MAX_PEERS, true, &evict);
    CHECK(v == 0 && evict);
    for (int i = 0; i < ML_MAX_PEERS; i++) peers[i].priority = true;
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, true, &evict) == -1 && !evict);

    /* A free slot is used before anything is evicted. */
    peers[11].active = false;
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, true, &evict) == 11 && !evict);
}

/* ---- rebind: the old network's STUN endpoint is never advertised again ------ */

static void test_rebind_clears_stun(void) {
    microlink_t *ml = new_ml(false);
    for (int pass = 0; pass < 2; pass++) {
        ml->stun_public_ip = 0xCB007101u;          /* 203.0.113.1, placeholder */
        ml->stun_public_port = 41641;
        ml->stun_has_ipv6 = true;
        ml->stun_public_ip6[0] = 0x20;
        ml->stun_public_port6 = 41641;
        ml->stun_nat_checked = true;
        ml->nat_mapping_varies = true;
        ml->netcheck.next_full = false;
        coord_state_t st = pass == 0 ? COORD_LONG_POLL : COORD_FAILED;
        coord_handle_command(ml, &st, ML_CMD_REBIND);
        CHECK(ml->stun_public_ip == 0 && ml->stun_public_port == 0);
        CHECK(!ml->stun_has_ipv6 && ml->stun_public_ip6[0] == 0 && ml->stun_public_port6 == 0);
        CHECK(!ml->stun_nat_checked && !ml->nat_mapping_varies);
        CHECK(ml->netcheck.next_full);
        /* Reconnects like FORCE_RECONNECT; a terminal error stays terminal. */
        CHECK(st == (pass == 0 ? COORD_RECONNECTING : COORD_FAILED));
    }
    free(ml);
}

/* ---- review fixes: home change always reconnects DERP; map edits; eviction --- */



static void test_home_change_reconnects_derp(void) {
    microlink_t *ml = new_ml(false);
    ml->derp_home_region = 902;
    uint32_t gen = ml->derp_target_gen;
    /* Registered, DERP not connected yet (a connect to the old region may be in flight). */
    ml->derp.connected = false;
    shim_event_bits_get = ML_EVT_COORD_REGISTERED;
    shim_event_bits_set = 0;
    coord_home_changed(ml, NULL, false);
    CHECK(shim_event_bits_set & ML_EVT_DERP_RECONNECT);
    CHECK(ml->derp_target_gen == gen + 1);
    /* Not registered: the DERP task is not connecting, so no reconnect request. */
    shim_event_bits_get = 0;
    shim_event_bits_set = 0;
    coord_home_changed(ml, NULL, false);
    CHECK(!(shim_event_bits_set & ML_EVT_DERP_RECONNECT) && ml->derp_target_gen == gen + 2);
    free(ml);
}

/* ---- round 3: priority peer home, connect backoff, late replies, stop, RTT ---- */

#define PRIO_KEY "nodekey:" \
    "1111111111111111111111111111111111111111111111111111111111111111"
#define OTHER_KEY "nodekey:" \
    "2222222222222222222222222222222222222222222222222222222222222222"

static void test_priority_peer_home(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    microlink_set_priority_peer_name(ml, "p4-dock.tail1234.ts.net");
    /* The priority peer's home is 902; we measure 901 as fastest. */
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":["
        "{\"Name\":\"laptop.tail1234.ts.net.\",\"Key\":\"" OTHER_KEY "\",\"HomeDERP\":901},"
        "{\"Name\":\"p4-dock.tail1234.ts.net.\",\"Key\":\"" PRIO_KEY "\",\"HomeDERP\":902}]}") == 0);
    CHECK(ml->derp_home_region == 902 && ml->netcheck.peer_region == 902);
    int64_t t = 4000000000LL;
    nc_round(ml, t, 0xC0000201u, 10000, 0xC6336401u, 90000);
    ml_netcheck_end(ml, t + 1000);
    CHECK(ml->netcheck.latency_home == 901 && ml->derp_home_region == 902);
    CHECK(!ml_netcheck_take_home_change(ml));

    /* The peer moves to 901: we follow, and the change is reported once. */
    parse_netmap(ml, "{\"PeersChangedPatch\":{\"" PRIO_KEY "\":{\"DERPRegion\":901}}}");
    CHECK(ml->derp_home_region == 901 && ml_netcheck_take_home_change(ml));
    CHECK(!ml_netcheck_take_home_change(ml));
    /* An unrelated peer's patch changes nothing. */
    parse_netmap(ml, "{\"PeersChangedPatch\":{\"" OTHER_KEY "\":{\"DERPRegion\":902}}}");
    CHECK(ml->derp_home_region == 901 && !ml_netcheck_take_home_change(ml));

    /* A region not in our map: the latency choice. */
    parse_netmap(ml, "{\"PeersChanged\":[{\"Name\":\"p4-dock.tail1234.ts.net.\","
                     "\"Key\":\"" PRIO_KEY "\",\"HomeDERP\":999}]}");
    CHECK(ml->netcheck.peer_region == 999 && ml->derp_home_region == 901);
    parse_netmap(ml, "{\"PeersChangedPatch\":{\"" PRIO_KEY "\":{\"DERPRegion\":902}}}");
    CHECK(ml->derp_home_region == 902);
    /* No home region (0): the latency choice. */
    parse_netmap(ml, "{\"PeersChanged\":[{\"Name\":\"p4-dock.tail1234.ts.net.\","
                     "\"Key\":\"" PRIO_KEY "\"}]}");
    CHECK(ml->derp_home_region == 901);
    parse_netmap(ml, "{\"PeersChangedPatch\":{\"" PRIO_KEY "\":{\"DERPRegion\":902}}}");
    CHECK(ml->derp_home_region == 902);

    /* Removed: the latency choice. */
    parse_netmap(ml, "{\"PeersRemoved\":[\"" PRIO_KEY "\"]}");
    CHECK(!ml->netcheck.peer_key_valid && ml->derp_home_region == 901);
    ml_netcheck_take_home_change(ml);

    /* A full peer list without it: the latency choice; by IP works as well. */
    parse_netmap(ml, "{\"Peers\":[{\"Name\":\"p4-dock.tail1234.ts.net.\","
                     "\"Key\":\"" PRIO_KEY "\",\"HomeDERP\":902}]}");
    CHECK(ml->derp_home_region == 902);
    parse_netmap(ml, "{\"Peers\":[{\"Name\":\"laptop.tail1234.ts.net.\","
                     "\"Key\":\"" OTHER_KEY "\",\"HomeDERP\":901}]}");
    CHECK(ml->derp_home_region == 901);
    microlink_set_priority_peer_name(ml, NULL);
    ml->config.priority_peer_ip = 0x64400003u;                  /* 100.64.0.3 */
    parse_netmap(ml, "{\"Peers\":[{\"Name\":\"x.tail1234.ts.net.\",\"Key\":\"" OTHER_KEY "\","
                     "\"Addresses\":[\"100.64.0.3/32\"],\"HomeDERP\":902}]}");
    CHECK(ml->derp_home_region == 902);
    /* No priority peer at all: the latency choice. */
    ml->config.priority_peer_ip = 0;
    parse_netmap(ml, "{\"Peers\":[]}");
    CHECK(ml->derp_home_region == 901);
    free(ml->netcheck.probes);
    free(ml);
}

static void test_derp_backoff(void) {
    /* util/backoff: min(n*n*10 ms, 5 s), times 0.5 to 1.5. */
    CHECK(ml_derp_backoff_ms(0, 0) == 0);
    CHECK(ml_derp_backoff_ms(1, 0) == 5 && ml_derp_backoff_ms(1, 0xFFFFFFFFu) == 14);
    CHECK(ml_derp_backoff_ms(3, 0x80000000u) == 90);
    CHECK(ml_derp_backoff_ms(100, 0) == 2500 && ml_derp_backoff_ms(100, 0xFFFFFFFFu) == 7499);
    CHECK(!ml_derp_backoff_capped(22) && ml_derp_backoff_capped(23));   /* 4840 / 5290 ms */

    /* A region whose connects keep failing loses the latency choice until a full round. */
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    int64_t t = 5000000000LL;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);
    ml->derp_failed_region = 902;
    t += 30000000;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 901);
    CHECK(ml->derp_regions[region_idx(ml, 902)].derp_failed);
    /* ...but the priority peer's region stays its choice: only it reaches that peer. */
    CHECK(ml_nc_effective_home(ml->derp_regions, ml->derp_region_count, 902, 901) == 902);
    /* A full round does not clear it, nor does a new map (no cycling through regions
     * when our own DERP reach is broken)... */
    ml_netcheck_request_full(ml);
    t += 30000000;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(!ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 901);
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    CHECK(ml->derp_regions[region_idx(ml, 902)].derp_failed);
    /* ...a connection to it that carries a frame does. */
    ml->derp_failed_region = 0;
    ml->derp_ok_region = 902;
    t += 30000000;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);
    CHECK(!ml->derp_regions[region_idx(ml, 902)].derp_failed && ml->derp_ok_region == 0);
    /* So does a rebind. */
    ml->derp_regions[region_idx(ml, 902)].derp_failed = true;
    ml->derp_failed_region = 902;
    coord_state_t st = COORD_LONG_POLL;
    coord_handle_command(ml, &st, ML_CMD_REBIND);
    CHECK(!ml->derp_regions[region_idx(ml, 902)].derp_failed && ml->derp_failed_region == 0);
    free(ml->netcheck.probes);
    free(ml);
}

/* DERP task connect retry (ml_derp_retry_*): connect only after coord decided the
 * home region; back off until a frame is read, not until the connect returns. */
static void test_derp_retry(void) {
    ml_derp_retry_t s = {0};
    /* A request from before registration does not count. */
    ml_derp_retry_on_bits(&s, false, true);
    ml_derp_retry_on_bits(&s, true, false);
    CHECK(!ml_derp_retry_due(&s, false, true, 0));
    /* Registered alone is not enough: the round may still move the home region. */
    ml_derp_retry_on_bits(&s, true, false);
    CHECK(!ml_derp_retry_due(&s, false, true, 0));
    ml_derp_retry_on_bits(&s, true, true);
    CHECK(ml_derp_retry_due(&s, false, true, 0));
    CHECK(!ml_derp_retry_due(&s, true, true, 0));

    /* The server accepts and the first read fails, again and again: the wait grows. */
    uint64_t now = 1000;
    uint32_t prev = 0;
    for (int i = 1; i <= 4; i++) {
        ml_derp_retry_attempt(&s, 904);
        uint32_t w = ml_derp_retry_failed(&s, now, 0x80000000u);
        CHECK(s.failures == i && w > prev && s.next_ms == now + w);
        CHECK(!ml_derp_retry_due(&s, false, true, now + w - 1) && ml_derp_retry_due(&s, false, true, now + w));
        prev = w;
        now += w;
    }
    /* A frame read resets it; a later loss starts from the first step again. */
    ml_derp_retry_attempt(&s, 904);
    CHECK(ml_derp_retry_frame(&s) && s.failures == 0);
    CHECK(!ml_derp_retry_frame(&s));
    CHECK(ml_derp_retry_failed(&s, now, 0x80000000u) == ml_derp_backoff_ms(1, 0x80000000u));
    /* Another region starts its own count. */
    ml_derp_retry_attempt(&s, 905);
    CHECK(s.failures == 0 && s.region == 905);

    /* Registration lost (rebind): no connect until coord asks again. */
    ml_derp_retry_on_bits(&s, false, false);
    ml_derp_retry_on_bits(&s, true, false);
    CHECK(!ml_derp_retry_due(&s, false, true, now + 100000));
    ml_derp_retry_on_bits(&s, true, true);
    CHECK(ml_derp_retry_due(&s, false, true, now));
}

static void test_effective_home_usable(void) {
    ml_derp_region_t regs[2];
    memset(regs, 0, sizeof(regs));
    regs[0].region_id = 901; regs[0].node_count = 1; strcpy(regs[0].nodes[0].hostname, "a");
    regs[1].region_id = 904; regs[1].node_count = 1; strcpy(regs[1].nodes[0].hostname, "b");
    CHECK(ml_nc_effective_home(regs, 2, 904, 901) == 904);
    regs[1].derp_failed = true;                        /* its DERP connects fail: still home */
    CHECK(ml_nc_effective_home(regs, 2, 904, 901) == 904);
    regs[1].derp_failed = false;
    regs[1].nodes[0].stun_only = true;                 /* no DERP node */
    CHECK(ml_nc_effective_home(regs, 2, 904, 901) == 901);
    CHECK(ml_nc_effective_home(regs, 2, 0, 901) == 901);
}

static void test_late_reply_dropped(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    int64_t t = 6000000000LL;
    int first = stub_binding_sent;
    nc_round(ml, t, 0xC0000201u, 20000, 0, 0);
    ml_netcheck_service(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL);
    ml_netcheck_end(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL);
    CHECK(ml->netcheck.last_count == 1);
    /* 902 answers after the round: taken (never endpoint STUN) but not a sample. */
    CHECK(nc_reply(ml, first, 0xC6336401u, t, ML_NC_STUN_TIMEOUT_MS * 1000LL + 5000));
    CHECK(ml->netcheck.lat_us[region_idx(ml, 902)] == 0 && ml->netcheck.last_count == 1);
    /* The next round forgets those txids. */
    ml_netcheck_request_full(ml);
    CHECK(ml_netcheck_begin(ml, t + 30000000));
    CHECK(!nc_reply(ml, first, 0xC6336401u, t, 30000000));
    ml_netcheck_abort(ml);
    CHECK(ml->netcheck.probes == NULL && !ml->netcheck.open);
    free(ml);
}

extern ml_dns_job_t *stub_dns_job;
extern int stub_dns_starts, stub_dns_detached;
extern esp_err_t stub_dns_start_result;

static void test_dns_async(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    stub_dns_job = NULL;
    stub_dns_starts = stub_dns_detached = 0;
    CHECK(fetch_with(ml, "{\"DERPMap\":{\"Regions\":{"
        "\"901\":{\"RegionID\":901,\"Nodes\":[{\"HostName\":\"d1.example.invalid\"},"
                                             "{\"HostName\":\"d1.example.invalid\"}]},"
        "\"902\":{\"RegionID\":902,\"Nodes\":[{\"HostName\":\"d2.example.invalid\"}]},"
        "\"903\":{\"RegionID\":903,\"Nodes\":[{\"HostName\":\"d3.example.invalid\"}]}}},"
        "\"Peers\":[]}") == 0);
    /* A local start failure is retried next round, never marked failed. */
    stub_dns_start_result = ESP_FAIL;
    CHECK(!ml_netcheck_begin(ml, 7000000000LL));
    CHECK(stub_dns_starts == 1 && !ml->netcheck.dns_job);
    stub_dns_start_result = ESP_OK;

    /* One job for all names (each once); nothing probed until they are in. */
    CHECK(!ml_netcheck_begin(ml, 7000000001LL));
    ml_dns_job_t *job = stub_dns_job;
    CHECK(job && job == ml->netcheck.dns_job && job->count == 3);
    CHECK(!strcmp(job->items[0].host, "d1.example.invalid"));
    CHECK(!ml_netcheck_begin(ml, 7000000002LL) && stub_dns_starts == 2);    /* one at a time */
    CHECK(!ml_netcheck_due(ml, 7000000));
    ml->netcheck.ran = true;
    ml->netcheck.next_full = false;
    ml->netcheck.last_round_ms = 7000000;
    CHECK(!ml_netcheck_due(ml, 7000001));

    /* Answers: an address, and two without one (name error or timeout, table full). */
    job->items[0].status = ML_DNS_OK; job->items[0].ipv4 = 0xC0000201u;
    job->items[1].status = ML_DNS_RETRY;
    job->items[2].status = ML_DNS_RETRY;
    job->done = true;
    CHECK(ml_netcheck_due(ml, 7000001));                /* the finished job asks for a round */
    int first = stub_binding_sent;
    CHECK(ml_netcheck_begin(ml, 7100000000LL) && ml_netcheck_service(ml, 7100000000LL) >= 0);
    CHECK(ml->derp_regions[0].nodes[0].stun_ipv4 == 0xC0000201u);
    CHECK(ml->derp_regions[0].nodes[1].stun_ipv4 == 0xC0000201u);
    CHECK(ml->derp_regions[1].nodes[0].stun_ipv4 == 0 && ml->derp_regions[2].nodes[0].stun_ipv4 == 0);
    CHECK(stub_binding_sent > first && stub_binding_ip[first] == 0xC0000201u);
    /* Both are asked again, together. */
    CHECK(stub_dns_job && stub_dns_starts == 3 && stub_dns_job->count == 2);
    CHECK(!strcmp(stub_dns_job->items[1].host, "d3.example.invalid"));

    /* Coord exit: round buffers freed, the job detached. */
    ml_netcheck_release(ml);
    CHECK(ml->netcheck.probes == NULL && ml->netcheck.dns_job == NULL && stub_dns_detached == 1);
    free(ml);
}

static void test_dns_answers_and_library_task(void) {
    ml_dns_item_t it = {0};
    ml_dns_item_answer(&it, false, 0);                   /* timeout or no such name */
    CHECK(it.status == ML_DNS_RETRY);
    ml_dns_item_answer(&it, true, 0xC0000201u);
    CHECK(it.status == ML_DNS_OK && it.ipv4 == 0xC0000201u);

    /* A finished job with nothing resolved does not ask for a round. */
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    stub_dns_job = NULL;
    CHECK(fetch_with(ml, "{\"DERPMap\":{\"Regions\":{"
        "\"901\":{\"RegionID\":901,\"Nodes\":[{\"HostName\":\"d1.example.invalid\"}]}}},"
        "\"Peers\":[]}") == 0);
    CHECK(!ml_netcheck_begin(ml, 7000000000LL) && stub_dns_job);
    ml->netcheck.next_full = false;
    ml->netcheck.last_round_ms = 7000000;
    stub_dns_job->items[0].status = ML_DNS_RETRY;
    ml_dns_job_set_done(stub_dns_job);
    CHECK(!ml_netcheck_due(ml, 7000001));
    stub_dns_job->items[0].status = ML_DNS_OK;
    CHECK(ml_netcheck_due(ml, 7000001));
    ml_netcheck_release(ml);
    free(ml);

    /* microlink_stop/destroy refuse to run on a MicroLink task. */
    microlink_t m = {0};
    int a, b;
    m.coord_task = &a;
    CHECK(ml_is_library_task(&m, &a) && !ml_is_library_task(&m, &b) && !ml_is_library_task(&m, NULL));
}

/* A one-region map whose DERP fails, then a rebind: in both modes the home stays the
 * only region and the DERP task keeps retrying it with backoff, never held. */
#define ONE_MAP "\"DERPMap\":{\"Regions\":{" \
    "\"901\":{\"RegionID\":901,\"RegionCode\":\"r1\",\"Nodes\":[" \
    "{\"HostName\":\"d1a.example.invalid\",\"IPv4\":\"192.0.2.1\"}]}}}"
static void single_region_stall(bool priority) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    if (priority) {
        microlink_set_priority_peer_name(ml, "p4-dock.tail1234.ts.net");
        CHECK(fetch_with(ml, "{" ONE_MAP ",\"Peers\":[{\"Name\":\"p4-dock.tail1234.ts.net.\","
                         "\"Key\":\"" PRIO_KEY "\",\"HomeDERP\":901}]}") == 0);
    } else {
        CHECK(fetch_with(ml, "{" ONE_MAP ",\"Peers\":[]}") == 0);
    }
    int64_t t = 9000000000LL;
    nc_round(ml, t, 0xC0000201u, 20000, 0, 0);
    ml_netcheck_end(ml, t + 1000);
    CHECK(ml->derp_home_region == 901);

    /* The DERP task fails until its backoff is at the maximum and reports 901. */
    ml_derp_retry_t s = {0};
    ml_derp_retry_on_bits(&s, true, true);
    uint64_t now = 0;
    while (!ml_derp_backoff_capped(s.failures)) {
        CHECK(ml_derp_retry_due(&s, false, true, now));
        ml_derp_retry_attempt(&s, ml->derp_home_region);
        now += ml_derp_retry_failed(&s, now, 0x80000000u);
    }
    ml->derp_failed_region = 901;
    for (int k = 0; k < 3; k++) {                       /* incremental and full rounds */
        t += ML_NC_FULL_INTERVAL_MS * 1000LL;
        nc_round(ml, t, 0xC0000201u, 20000, 0, 0);
        ml_netcheck_end(ml, t + 1000);
        CHECK(ml->derp_home_region == 901);
        CHECK(ml_derp_retry_due(&s, false, true, now + ML_DERP_BACKOFF_MAX_MS * 3 / 2));
    }
    /* The only region excluded is every region excluded: forgotten, still retried. */
    CHECK(!ml->derp_regions[0].derp_failed);

    /* Rebind: exclusions forgotten, registration lost, then a new connect request. */
    coord_state_t st = COORD_LONG_POLL;
    coord_handle_command(ml, &st, ML_CMD_REBIND);
    CHECK(!ml->derp_regions[0].derp_failed && ml->derp_failed_region == 0);
    ml_derp_retry_on_bits(&s, false, false);
    CHECK(!ml_derp_retry_due(&s, false, false, now + 1000000));
    ml_derp_retry_on_bits(&s, true, true);
    t += 60000000;
    nc_round(ml, t, 0xC0000201u, 20000, 0, 0);
    ml_netcheck_end(ml, t + 1000);
    CHECK(ml->derp_home_region == 901 && ml_derp_retry_due(&s, false, true, now));
    /* Still failing after the rebind: retried, never held. */
    ml_derp_retry_attempt(&s, 901);
    uint32_t w = ml_derp_retry_failed(&s, now, 0x80000000u);
    CHECK(ml_derp_retry_due(&s, false, true, now + w));
    free(ml->netcheck.probes);
    free(ml);
}

static void test_single_region_stall(void) {
    single_region_stall(true);
    single_region_stall(false);
}

/* The priority peer's region is home through connect failures and full rounds. */
static void test_priority_region_unconditional(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    microlink_set_priority_peer_name(ml, "p4-dock.tail1234.ts.net");
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[{\"Name\":\"p4-dock.tail1234.ts.net.\","
                     "\"Key\":\"" PRIO_KEY "\",\"HomeDERP\":902}]}") == 0);
    int64_t t = 9500000000LL;
    for (int k = 0; k < 4; k++) {
        ml->derp_failed_region = 902;
        nc_round(ml, t, 0xC0000201u, 20000, 0xC6336401u, 80000);
        ml_netcheck_end(ml, t + 1000);
        CHECK(ml->derp_home_region == 902 && ml->netcheck.latency_home == 901);
        t += ML_NC_FULL_INTERVAL_MS * 1000LL;
    }
    /* 902 is excluded only from the latency choice; a frame on it lifts that. */
    CHECK(ml->derp_regions[region_idx(ml, 902)].derp_failed);
    ml->derp_failed_region = 0;
    ml->derp_ok_region = 902;
    nc_round(ml, t, 0xC0000201u, 20000, 0xC6336401u, 80000);
    ml_netcheck_end(ml, t + 1000);
    CHECK(!ml->derp_regions[region_idx(ml, 902)].derp_failed && ml->derp_ok_region == 0);
    /* The peer leaves: the latency choice. */
    parse_netmap(ml, "{\"PeersRemoved\":[\"" PRIO_KEY "\"]}");
    CHECK(ml->derp_home_region == 901);
    free(ml->netcheck.probes);
    free(ml);
}

/* Offline (no STUN reply in the round): a DERP failure is not the region's fault.
 * microlink_start clears whatever the last run left. */
static void test_offline_and_start(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    int64_t t = 9800000000LL;
    ml->derp_failed_region = 901;
    nc_round(ml, t, 0, 0, 0, 0);
    ml_netcheck_end(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL);
    CHECK(!ml->derp_regions[region_idx(ml, 901)].derp_failed && ml->derp_failed_region == 0);
    ml->derp_regions[region_idx(ml, 901)].derp_failed = true;
    ml->derp_failed_region = ml->derp_ok_region = 901;
    ml_netcheck_forget_derp_failures(ml);
    CHECK(!ml->derp_regions[region_idx(ml, 901)].derp_failed && !ml->derp_failed_region &&
          !ml->derp_ok_region);
    free(ml->netcheck.probes);
    free(ml);
}

/* Latency mode: once every usable region is excluded, the exclusions are dropped and
 * the measured latency decides again (not the first region of the map). */
#define TWO_MAP "\"DERPMap\":{\"Regions\":{" \
    "\"901\":{\"RegionID\":901,\"Nodes\":[{\"HostName\":\"d1a.example.invalid\",\"IPv4\":\"192.0.2.1\"}]}," \
    "\"902\":{\"RegionID\":902,\"Nodes\":[{\"HostName\":\"d2.example.invalid\",\"IPv4\":\"198.51.100.1\"}]}}}"
static void test_all_excluded_forgotten(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" TWO_MAP ",\"Peers\":[]}") == 0);
    int64_t t = 9900000000LL;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);
    ml->derp_failed_region = 902;
    t += 30000000;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 901);
    CHECK(ml->derp_regions[region_idx(ml, 902)].derp_failed);
    ml->derp_failed_region = 901;                       /* now 901 fails as well */
    t += 30000000;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);
    CHECK(!ml->derp_regions[region_idx(ml, 901)].derp_failed);
    CHECK(!ml->derp_regions[region_idx(ml, 902)].derp_failed && ml->derp_failed_region == 0);
    free(ml->netcheck.probes);
    free(ml);
}

static void test_priority_cleared(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    microlink_set_priority_peer_name(ml, "p4-dock.tail1234.ts.net");
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[{\"Name\":\"p4-dock.tail1234.ts.net.\","
                     "\"Key\":\"" PRIO_KEY "\",\"Addresses\":[\"100.64.0.3/32\"],\"HomeDERP\":902}]}") == 0);
    CHECK(ml->derp_home_region == 902);
    ml_netcheck_take_home_change(ml);
    ml->netcheck.latency_home = 901;
    /* Still named by CONFIG_ML_PRIORITY_PEER_IP: kept. */
    ml->config.priority_peer_ip = 0x64400003u;
    shim_event_bits_get = ML_EVT_PRIORITY_CLEARED;
    coord_priority_cleared(ml);
    CHECK(ml->derp_home_region == 902 && !ml_netcheck_take_home_change(ml));
    CHECK(!(shim_event_bits_get & ML_EVT_PRIORITY_CLEARED));        /* taken once */
    /* Not named any more: the latency choice at once, no netmap re-read. */
    ml->config.priority_peer_ip = 0;
    coord_priority_cleared(ml);                                     /* no bit: nothing */
    CHECK(ml->derp_home_region == 902);
    shim_event_bits_get = ML_EVT_PRIORITY_CLEARED;
    coord_priority_cleared(ml);
    CHECK(ml->derp_home_region == 901 && ml_netcheck_take_home_change(ml));
    shim_event_bits_get = 0;
    free(ml);
}

extern void *stub_rx_queue;
extern int stub_rx_avail, stub_rx_taken;

static void test_stop_and_drain(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    ml_netcheck_take_home_change(ml);
    uint16_t home = ml->derp_home_region;
    /* Shutdown during a round: no end-of-round side effects. */
    shim_event_bits_get = ML_EVT_SHUTDOWN_REQUEST | ML_EVT_COORD_REGISTERED;
    shim_event_bits_set = 0;
    CHECK(!coord_run_netcheck(ml, NULL, false));
    CHECK(ml->netcheck.probes == NULL && ml->netcheck.last_count == 0);
    CHECK(ml->derp_home_region == home && !(shim_event_bits_set & ML_EVT_DERP_RECONNECT));
    shim_event_bits_get = 0;

    /* The long-poll drain takes at most the queue depth per pass. */
    int q;
    ml->stun_rx_queue = &q;
    stub_rx_queue = &q;
    stub_rx_avail = 3 * ML_STUN_RX_QUEUE_DEPTH;
    stub_rx_taken = 0;
    coord_drain_stun(ml, NULL);
    CHECK(stub_rx_taken == ML_STUN_RX_QUEUE_DEPTH);
    stub_rx_avail = 1;
    stub_rx_taken = 0;
    coord_drain_stun(ml, NULL);
    CHECK(stub_rx_taken == 1);
    stub_rx_queue = NULL;
    free(ml);
}

static void test_rtt_from_receive_time(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    /* Stamp conversion: low 32 bits back to the full clock. */
    ml_rx_packet_t pkt = {0};
    int64_t now = esp_timer_get_time();
    pkt.rx_us = (uint32_t)(now - 40000);
    int64_t back = coord_rx_time_us(&pkt);
    CHECK(back == now - 40000);

    /* A reply stamped 13 ms after the send counts 13 ms, however late it is dequeued. */
    int64_t t0 = esp_timer_get_time();
    int first = stub_binding_sent;
    CHECK(ml_netcheck_begin(ml, t0) && ml_netcheck_service(ml, t0) >= 0);
    uint8_t r[20] = {0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
    memcpy(r + 8, stub_binding_txid[first], 12);
    pkt.data = r;
    pkt.len = sizeof(r);
    pkt.rx_us = (uint32_t)(t0 + 13000);
    usleep(30000);                                  /* dequeued 30 ms later */
    coord_handle_stun_packet(ml, NULL, &pkt, false);
    int ri = ml->netcheck.probes[0].region;
    uint32_t lat = ml->netcheck.lat_us[ri];
    CHECK(lat > 12000 && lat <= 13000);
    ml_netcheck_abort(ml);
    free(ml);
}

static void test_map_edits(void) {
    microlink_t *ml = new_ml(false);
    ml->t_stun_interval_ms = 23000;
    CHECK(fetch_with(ml, "{" NC_MAP ",\"Peers\":[]}") == 0);
    int64_t t = 3000000000LL;
    nc_round(ml, t, 0xC0000201u, 80000, 0xC6336401u, 20000);
    CHECK(ml_netcheck_end(ml, t + 1000) && ml->derp_home_region == 902);

    /* The map loses region 902: home moves to the first usable region, and the next
     * round reports the change even if it measures nothing (DERP must reconnect). */
    CHECK(fetch_with(ml, "{\"DERPMap\":{\"Regions\":{\"901\":{\"RegionID\":901,\"Nodes\":["
                         "{\"HostName\":\"d1a.example.invalid\",\"IPv4\":\"192.0.2.1\"}]}}},"
                         "\"Peers\":[]}") == 0);
    CHECK(ml->derp_home_region == 901 && ml->derp_region_count == 1);
    CHECK(ml->derp_regions[0].nodes[0].stun_ipv4 == 0xC0000201u);   /* kept, no new lookup */
    t += 30000000;
    nc_round(ml, t, 0, 0, 0, 0);
    CHECK(ml_netcheck_end(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL) && ml->derp_home_region == 901);
    t += 30000000;
    nc_round(ml, t, 0, 0, 0, 0);
    CHECK(!ml_netcheck_end(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL));    /* reported once */

    /* An empty Regions map is ignored: home and regions stay. */
    CHECK(fetch_with(ml, "{\"DERPMap\":{\"Regions\":{}},\"Peers\":[]}") == 0);
    CHECK(ml->derp_home_region == 901 && ml->derp_region_count == 1);
    free(ml);
}

static void test_eviction_prefers_idle_peers(void) {
    ml_peer_t peers[ML_MAX_PEERS];
    bool evict;
    memset(peers, 0, sizeof(peers));
    for (int i = 0; i < ML_MAX_PEERS; i++) {
        peers[i].active = true;
        peers[i].has_session = true;
        peers[i].last_send_ms = 5000 + i;
    }
    /* Oldest activity overall is peer 0, but it has a session; peer 9 has none. */
    peers[0].last_send_ms = 10;
    peers[9].has_session = false;
    peers[9].last_send_ms = 9000;
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, true, &evict) == 9 && evict);
    /* Among peers without a session, the least recently active goes. */
    peers[12].has_session = false;
    peers[12].last_send_ms = 100;
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, true, &evict) == 12 && evict);
    /* Only live sessions left: the least recently active one, as the last resort. */
    peers[9].has_session = peers[12].has_session = true;
    CHECK(ml_peer_admit_slot(peers, ML_MAX_PEERS, true, &evict) == 0 && evict);
}

int main(void) {
    test_home_change_reconnects_derp();
    test_priority_peer_home();
    test_derp_backoff();
    test_late_reply_dropped();
    test_dns_async();
    test_derp_retry();
    test_effective_home_usable();
    test_priority_cleared();
    test_single_region_stall();
    test_priority_region_unconditional();
    test_offline_and_start();
    test_all_excluded_forgotten();
    test_dns_answers_and_library_task();
    test_stop_and_drain();
    test_rtt_from_receive_time();
    test_map_edits();
    test_eviction_prefers_idle_peers();
    test_rebind_clears_stun();
    test_priority_name_match();
    test_priority_setter();
    test_priority_marked_on_every_netmap();
    test_netmap_never_drops_updates();
    test_priority_admission();
    test_netcheck_plan();
    test_netcheck_choice();
    test_commands();
    test_key_expired();
    test_begin_login();
    test_poll_map_update();
    test_fetch_self_node();
    test_recv_results();
    printf("%d coord checks, %d failed\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
