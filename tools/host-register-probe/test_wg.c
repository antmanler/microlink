/**
 * Tests of wireguard-lwip's handshake triggering and give-up, run on the host.
 *
 * wireguardif.c, wireguard.c and crypto.c are #included and compiled unchanged
 * against ESP-IDF's lwIP headers (shim-lwip/ holds the options). This file
 * supplies the dozen lwIP functions they link, a settable clock, and a DERP
 * output hook that records each packet sent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wireguardif.c"
#include "wireguard.c"
#include "crypto.c"

static int g_failed, g_total;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_total++;                                                           \
        if (!(cond)) {                                                       \
            g_failed++;                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* ---- platform and lwIP stand-ins ----------------------------------------- */

static uint32_t g_now_ms = 1000;

uint32_t wireguard_sys_now(void) { return g_now_ms; }
void wireguard_tai64n_now(uint8_t *output) {
    static uint32_t n;
    memset(output, 0, 12);
    n++;
    output[8] = (uint8_t)(n >> 24); output[9] = (uint8_t)(n >> 16);
    output[10] = (uint8_t)(n >> 8); output[11] = (uint8_t)n;
}
void wireguard_random_bytes(void *bytes, size_t size) {
    uint8_t *b = bytes;
    for (size_t i = 0; i < size; i++) b[i] = (uint8_t)rand();
}
bool wireguard_is_under_load(void) { return false; }

const ip_addr_t ip_addr_any = IPADDR4_INIT(0);
u32_t lwip_htonl(u32_t x) { return __builtin_bswap32(x); }

void *mem_malloc(mem_size_t size) { return malloc(size); }
void *mem_calloc(mem_size_t count, mem_size_t size) { return calloc(count, size); }
void mem_free(void *mem) { free(mem); }

struct pbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type) {
    (void)layer; (void)type;
    struct pbuf *p = calloc(1, sizeof(*p) + length);
    if (!p) return NULL;
    p->payload = (uint8_t *)(p + 1);
    p->len = p->tot_len = length;
    return p;
}
u8_t pbuf_free(struct pbuf *p) { free(p); return 1; }
u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset) {
    if (offset >= p->tot_len) return 0;
    if (len > p->tot_len - offset) len = p->tot_len - offset;
    memcpy(dataptr, (const uint8_t *)p->payload + offset, len);
    return len;
}
err_t pbuf_take(struct pbuf *buf, const void *dataptr, u16_t len) {
    if (len > buf->tot_len) return ERR_ARG;
    memcpy(buf->payload, dataptr, len);
    return ERR_OK;
}

/* Link state as lwIP keeps it (netif.c sets/clears NETIF_FLAG_LINK_UP). */
void netif_set_link_up(struct netif *netif) { netif->flags |= NETIF_FLAG_LINK_UP; }
void netif_set_link_down(struct netif *netif) { netif->flags &= (u8_t)~NETIF_FLAG_LINK_UP; }

/* lwIP routes a packet to a netif only when it is up and its link is up
 * (IDF 5.5.3 lwip ip4.c ip4_route, lwip_default_hooks.c). Anything else goes out
 * the default route: for the tailnet range, a leak to the LAN gateway. */
static bool routes_to(const struct netif *n) { return netif_is_up(n) && netif_is_link_up(n); }
void sys_timeout(u32_t msecs, sys_timeout_handler handler, void *arg) { (void)msecs; (void)handler; (void)arg; }
void sys_untimeout(sys_timeout_handler handler, void *arg) { (void)handler; (void)arg; }
struct udp_pcb *udp_new(void) { return NULL; }
err_t udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) { (void)pcb; (void)ipaddr; (void)port; return ERR_VAL; }
void udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif) { (void)pcb; (void)netif; }
void udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg) { (void)pcb; (void)recv; (void)recv_arg; }
void udp_remove(struct udp_pcb *pcb) { (void)pcb; }
static int g_direct_initiations;
err_t udp_sendto(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip, u16_t dst_port) {
    (void)pcb; (void)dst_ip; (void)dst_port;
    if (p->tot_len > 0 && ((const uint8_t *)p->payload)[0] == MESSAGE_HANDSHAKE_INITIATION) g_direct_initiations++;
    return ERR_OK;
}

/* DERP output: count handshake initiations (message type 1). */
static int g_initiations;
static err_t derp_out(const uint8_t *key, const uint8_t *data, size_t len, void *ctx) {
    (void)key; (void)ctx;
    if (len > 0 && data[0] == MESSAGE_HANDSHAKE_INITIATION) g_initiations++;
    return ERR_OK;
}

/* ---- fixture --------------------------------------------------------------- */

static struct netif g_netif;
static u8_t g_peer;

static void setup(void) {
    /* Fixed placeholder keys, not real ones. */
    uint8_t priv[32], peer_priv[32], peer_pub[32];
    char priv_b64[64], pub_b64[64];
    size_t olen;
    memset(priv, 0x41, sizeof(priv));
    memset(peer_priv, 0x42, sizeof(peer_priv));
    wireguard_clamp_private_key(peer_priv);
    wireguard_generate_public_key(peer_pub, peer_priv);
    olen = sizeof(priv_b64);
    wireguard_base64_encode(priv, 32, priv_b64, &olen);
    olen = sizeof(pub_b64);
    wireguard_base64_encode(peer_pub, 32, pub_b64, &olen);

    static struct wireguardif_init_data init;
    init.private_key = priv_b64;
    memset(&g_netif, 0, sizeof(g_netif));
    g_netif.state = &init;
    wireguardif_disable_socket_bind();
    if (wireguardif_init(&g_netif) != ERR_OK) { printf("wireguardif_init failed\n"); exit(2); }
    wireguardif_set_derp_output(&g_netif, derp_out, NULL);
    /* As ml_wg_mgr.c wg_init_interface(): the netif is brought up with its link up. */
    g_netif.flags |= NETIF_FLAG_UP;
    netif_set_link_up(&g_netif);

    struct wireguardif_peer p;
    wireguardif_peer_init(&p);
    p.public_key = pub_b64;
    IP_ADDR4(&p.allowed_ip, 100, 64, 0, 2);
    IP_ADDR4(&p.allowed_mask, 255, 255, 255, 255);
    ip_addr_set_any(false, &p.endpoint_ip);      /* no direct endpoint: DERP */
    p.endport_port = 0;
    g_peer = WIREGUARDIF_INVALID_INDEX;
    if (wireguardif_add_peer(&g_netif, &p, &g_peer) != ERR_OK) { printf("add_peer failed\n"); exit(2); }
}

static struct wireguard_peer *peer(void) {
    return &((struct wireguard_device *)g_netif.state)->peers[g_peer];
}

static err_t send_app_packet(void) {
    struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, 40, PBUF_RAM);
    memset(q->payload, 0x45, 40);
    ip4_addr_t dst;
    IP4_ADDR(&dst, 100, 64, 0, 2);
    err_t r = g_netif.output(&g_netif, q, &dst);
    pbuf_free(q);
    return r;
}

/* Run the timer for `seconds`, in wg_mgr's 400 ms steps. */
static void run_timer(int seconds) {
    for (int t = 0; t < seconds * 1000; t += 400) {
        g_now_ms += 400;
        wireguardif_periodic(&g_netif);
    }
}

/* ---- tests ------------------------------------------------------------------ */

static void test_outbound_starts_handshake_and_cap_stops_it(void) {
    CHECK(MAX_TIMER_HANDSHAKES == 18);                 /* wireguard-go 90 s / 5 s */
    CHECK(MAX_HANDSHAKE_INITIATIONS == 20);

    /* No session and nobody asked: the passive peer sends nothing, and the netif
     * still takes tailnet packets (no link-down for lack of a session). */
    run_timer(30);
    CHECK(g_initiations == 0);
    CHECK(routes_to(&g_netif));
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_NONE);

    /* An app packet without a session is dropped, never blocks, and marks the peer. */
    CHECK(send_app_packet() == ERR_CONN);
    CHECK(g_initiations == 0);
    CHECK(peer()->send_requested);
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_INITIATE);
    CHECK(!peer()->send_requested);
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_NONE);

    /* The owner sends it (ml_wg_mgr_trigger_handshake starts with connect_derp). */
    CHECK(wireguardif_connect_derp(&g_netif, g_peer) == ERR_OK);
    CHECK(g_initiations == 1);

    /* Unanswered: retried every REKEY_TIMEOUT until the cap, then silent. */
    run_timer(REKEY_ATTEMPT_TIME + 30);
    CHECK(g_initiations == MAX_HANDSHAKE_INITIATIONS);
    CHECK(!peer()->active);
    run_timer(120);
    CHECK(g_initiations == MAX_HANDSHAKE_INITIATIONS);

    /* A later packet starts a new cycle with the same cap. */
    CHECK(send_app_packet() == ERR_CONN);
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_INITIATE);
    CHECK(wireguardif_connect_derp(&g_netif, g_peer) == ERR_OK);
    run_timer(REKEY_ATTEMPT_TIME + 30);
    CHECK(g_initiations == 2 * MAX_HANDSHAKE_INITIATIONS);
    CHECK(!peer()->active);
    CHECK(routes_to(&g_netif));
}

static void test_send_within_rekey_timeout_restarts_retries(void) {
    int before = g_initiations;
    CHECK(send_app_packet() == ERR_CONN);
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_INITIATE);
    CHECK(wireguardif_connect_derp(&g_netif, g_peer) == ERR_OK);
    run_timer(REKEY_TIMEOUT * 10);                     /* some retries spent */
    CHECK(peer()->handshake_attempts > 1);

    /* Inside REKEY_TIMEOUT of the last initiation: no extra initiation now, but the
     * give-up count restarts and the timer keeps retrying (wireguard-go resets the
     * count on every send, then rate-limits). */
    peer()->last_initiation_tx = g_now_ms;
    CHECK(send_app_packet() == ERR_CONN);
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_RETRYING);
    CHECK(peer()->handshake_attempts == 0 && peer()->active);
    int at_restart = g_initiations;
    run_timer(REKEY_ATTEMPT_TIME + 30);
    CHECK(g_initiations - at_restart == MAX_HANDSHAKE_INITIATIONS);
    CHECK(g_initiations > before);
}

static void test_session_present_needs_nothing(void) {
    peer()->send_requested = true;
    peer()->curr_keypair.valid = true;
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_NONE);
    CHECK(!peer()->send_requested);
    peer()->curr_keypair.valid = false;
    CHECK(wireguardif_take_send_request(&g_netif, WIREGUARD_MAX_PEERS - 1) == WIREGUARDIF_SEND_NONE);
}

/* A peer that had a session, went away, and came back: the previous keypair dies at
 * REJECT_AFTER_TIME, so the peer no longer looks up and a send starts a handshake
 * even after an earlier cycle gave up. */
static void test_peer_back_from_away(void) {
    struct wireguard_peer *pp = peer();
    pp->active = false;                       /* an earlier cycle gave up */
    pp->curr_keypair.valid = false;
    pp->prev_keypair.valid = true;            /* left over from the old session */
    pp->prev_keypair.keypair_millis = g_now_ms;
    CHECK(wireguardif_peer_is_up(&g_netif, g_peer, NULL, NULL) == ERR_OK);
    run_timer(REJECT_AFTER_TIME + 1);
    CHECK(!pp->prev_keypair.valid);
    CHECK(wireguardif_peer_is_up(&g_netif, g_peer, NULL, NULL) == ERR_CONN);
    CHECK(routes_to(&g_netif));

    CHECK(send_app_packet() == ERR_CONN);
    CHECK(wireguardif_take_send_request(&g_netif, g_peer) == WIREGUARDIF_SEND_INITIATE);
    CHECK(pp->active && pp->handshake_attempts == 0);
}

/* One initiation on one path: DERP unless a confirmed direct endpoint is given. */
static void test_initiate_single_path(void) {
    int derp0 = g_initiations, direct0 = g_direct_initiations;
    g_now_ms += REKEY_TIMEOUT * 1000;
    CHECK(wireguardif_initiate(&g_netif, g_peer, NULL, 0) == ERR_OK);
    CHECK(g_initiations == derp0 + 1 && g_direct_initiations == direct0);
    CHECK(ip_addr_isany(&peer()->ip));

    ip_addr_t ep;
    IP_ADDR4(&ep, 192, 0, 2, 9);              /* documentation address */
    g_now_ms += REKEY_TIMEOUT * 1000;
    CHECK(wireguardif_initiate(&g_netif, g_peer, &ep, 41641) == ERR_OK);
    CHECK(g_initiations == derp0 + 1 && g_direct_initiations == direct0 + 1);
    CHECK(!ip_addr_isany(&peer()->ip) && peer()->port == 41641);

    /* Direct path lost without a session: retries go to DERP, nothing sent now. */
    CHECK(wireguardif_use_derp(&g_netif, g_peer) == ERR_OK);
    CHECK(ip_addr_isany(&peer()->ip) && peer()->port == 0);
    CHECK(g_initiations == derp0 + 1 && g_direct_initiations == direct0 + 1);
}

/* The DISCO pong one-shot asks this before sending a direct initiation. */
static void test_initiation_pending(void) {
    g_now_ms += REKEY_TIMEOUT * 1000;
    CHECK(!wireguardif_initiation_pending(&g_netif, g_peer));
    CHECK(wireguardif_initiate(&g_netif, g_peer, NULL, 0) == ERR_OK);       /* over DERP */
    CHECK(wireguardif_initiation_pending(&g_netif, g_peer));
    g_now_ms += REKEY_TIMEOUT * 1000 - 1;
    CHECK(wireguardif_initiation_pending(&g_netif, g_peer));
    g_now_ms += 2;
    CHECK(!wireguardif_initiation_pending(&g_netif, g_peer));             /* timed out */
    CHECK(wireguardif_initiate(&g_netif, g_peer, NULL, 0) == ERR_OK);
    peer()->handshake.valid = false;                                      /* answered */
    CHECK(!wireguardif_initiation_pending(&g_netif, g_peer));
    CHECK(!wireguardif_initiation_pending(&g_netif, WIREGUARD_MAX_PEERS - 1));
}

int main(void) {
    setup();
    test_outbound_starts_handshake_and_cap_stops_it();
    test_send_within_rekey_timeout_restarts_retries();
    test_session_present_needs_nothing();
    test_peer_back_from_away();
    test_initiate_single_path();
    test_initiation_pending();
    printf("%d wireguard checks, %d failed\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
