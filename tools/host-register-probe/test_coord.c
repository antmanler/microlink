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

int main(void) {
    test_commands();
    test_key_expired();
    test_begin_login();
    test_poll_map_update();
    test_fetch_self_node();
    test_recv_results();
    printf("%d coord checks, %d failed\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
