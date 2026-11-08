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
    CHECK(ml->netcheck.last_count == 2 && ml->netcheck.probes == NULL);
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
    CHECK(!ml_netcheck_end(ml, t + ML_NC_STUN_TIMEOUT_MS * 1000LL) && ml->derp_home_region == 907);
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

extern void *stub_cmd_queue, *stub_peer_queue;
extern int stub_cmd_sent, stub_cmd_last;
extern ml_peer_update_t *stub_peer_updates[64];
extern int stub_peer_update_count;

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
    CHECK(stub_cmd_sent == 1);
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

static void parse_netmap(microlink_t *ml, const char *json) {
    for (int i = 0; i < stub_peer_update_count; i++) free(stub_peer_updates[i]);
    stub_peer_update_count = 0;
    cJSON *root = cJSON_Parse(json);
    parse_peers_from_map_response(ml, root);
    cJSON_Delete(root);
}

static void test_priority_marked_on_every_netmap(void) {
    microlink_t *ml = new_ml(false);
    int peerq;
    ml->peer_update_queue = &peerq;
    stub_peer_queue = &peerq;
    const char *map = "{\"Peers\":["
        "{\"Name\":\"laptop.tail1234.ts.net.\",\"Addresses\":[\"100.64.0.2/32\"]},"
        "{\"Name\":\"P4-Dock.tail1234.ts.net.\",\"Addresses\":[\"100.64.0.3/32\"]},"
        "{\"Name\":\"p4-dock-2.tail1234.ts.net.\",\"Addresses\":[\"100.64.0.4/32\"]}]}";

    parse_netmap(ml, map);                                 /* no name set: none marked */
    CHECK(stub_peer_update_count == 3);
    for (int i = 0; i < 3; i++) CHECK(!stub_peer_updates[i]->priority);

    microlink_set_priority_peer_name(ml, "p4-dock.tail1234.ts.net");
    parse_netmap(ml, map);
    CHECK(stub_peer_update_count == 3);
    CHECK(!stub_peer_updates[0]->priority && stub_peer_updates[1]->priority &&
          !stub_peer_updates[2]->priority);

    /* A changed name moves the mark on the next netmap. */
    microlink_set_priority_peer_name(ml, "laptop.tail1234.ts.net.");
    parse_netmap(ml, map);
    CHECK(stub_peer_updates[0]->priority && !stub_peer_updates[1]->priority);

    parse_netmap(ml, "{}");
    stub_peer_queue = NULL;
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

int main(void) {
    test_priority_name_match();
    test_priority_setter();
    test_priority_marked_on_every_netmap();
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
