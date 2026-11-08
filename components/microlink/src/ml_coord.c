/**
 * @file ml_coord.c
 * @brief Coordination Task - Control Plane Client
 *
 * Owns ALL Noise protocol state (keys, nonces) exclusively.
 * Handles registration, MapResponse parsing, endpoint updates.
 * Runs as a state machine on Core 1.
 *
 * Protocol flow:
 *   1. DNS resolve controlplane.tailscale.com
 *   2. TCP connect to port 80 (NOT TLS - Noise provides encryption)
 *   3. HTTP/1.1 Upgrade with Noise msg1 in X-Tailscale-Handshake header
 *   4. Read Noise msg2 from upgrade response body
 *   5. Derive transport keys, send H2 preface (encrypted via Noise)
 *   6. Send RegisterRequest (Noise-encrypted H2 HEADERS+DATA)
 *   7. Parse RegisterResponse
 *   8. Send MapRequest, parse MapResponse (peers)
 *   9. Long-poll for updates
 *
 * Reference: tailscale/control/controlclient/auto.go
 *            tailscale/control/controlclient/direct.go
 */

#include "microlink_internal.h"
#include "ml_register.h"
#include "x25519.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "cJSON.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "mbedtls/base64.h"
#include <string.h>
#include <errno.h>

static const char *TAG = "ml_coord";

/* Effective control plane host: NVS override or compiled default */
#define CTRL_HOST(ml) ((ml)->ctrl_host[0] ? (ml)->ctrl_host : ML_CTRL_HOST)

/* NodeKeyChallenge from EarlyNoise (stored between handshake and register) */
static uint8_t s_node_key_challenge[32] = {0};
static bool s_has_node_key_challenge = false;

/* Coordination state machine */
typedef enum {
    COORD_IDLE,
    COORD_STUN_PROBE,
    COORD_DNS_RESOLVE,
    COORD_TCP_CONNECT,
    COORD_NOISE_HANDSHAKE,
    COORD_H2_PREFACE,
    COORD_REGISTER,
    COORD_FETCH_PEERS,
    COORD_LONG_POLL,
    COORD_RECONNECTING,
    COORD_LOGIN_WAIT,       /* AuthURL issued: non-blocking Followup wait (NEEDS_LOGIN) */
    COORD_FAILED,           /* terminal error published (ERROR); waits for microlink_retry() */
} coord_state_t;

/* ============================================================================
 * Helper: hex encoding for keys
 * ========================================================================== */

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    static const char hextab[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hextab[bytes[i] >> 4];
        hex[i * 2 + 1] = hextab[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%2x", &val) != 1) return -1;
        bytes[i] = (uint8_t)val;
    }
    return hex_len / 2;
}

/* ============================================================================
 * TCP I/O helpers for coord socket (owned exclusively by this task)
 * ========================================================================== */

static int coord_send(microlink_t *ml, const uint8_t *data, size_t len) {
    /* Set send timeout to prevent indefinite blocking (v1 uses MSG_DONTWAIT) */
    struct timeval snd_tv = { .tv_sec = 5, .tv_usec = 0 };
    ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv));

    size_t sent = 0;
    while (sent < len) {
        int n = ml_send(ml->coord_sock, data + sent, len - sent, 0);
        if (n <= 0) {
            ESP_LOGE(TAG, "coord_send failed: sent=%d/%d n=%d errno=%d",
                     (int)sent, (int)len, n, errno);
            return -1;
        }
        sent += n;
    }
    return 0;
}

/* Negative return codes of coord_recv() and noise_recv(). The caller decides on
 * these, never on errno: a stale EAGAIN must not turn a dead stream into "idle". */
enum {
    COORD_RECV_FATAL = -1,  /* closed, failed, or a partial read left the stream misaligned */
    COORD_RECV_IDLE  = -2,  /* nothing consumed: the receive timeout expired before the first byte */
};

static int coord_recv(microlink_t *ml, uint8_t *buf, size_t len) {
    size_t recvd = 0;
    int retries = 0;
    while (recvd < len) {
        int n = ml_recv(ml->coord_sock, buf + recvd, len - recvd, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (recvd == 0) {
                /* No data consumed yet: a timeout is fine, the caller can retry */
                return COORD_RECV_IDLE;
            }
            /* Partial data consumed: we MUST finish this read or the Noise frame
             * stream is misaligned. Retry with backoff. */
            if (++retries > 300) {  /* ~3 seconds */
                ESP_LOGE(TAG, "coord_recv partial timeout: %d/%d bytes",
                         (int)recvd, (int)len);
                return COORD_RECV_FATAL;
            }
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (n <= 0) {   /* 0 = peer closed, <0 = socket error */
            ESP_LOGE(TAG, "coord_recv failed: %d (errno %d, recvd %d/%d)",
                     n, n < 0 ? errno : 0, (int)recvd, (int)len);
            return COORD_RECV_FATAL;
        }
        recvd += n;
        retries = 0;  /* Reset on successful read */
    }
    return 0;
}

/* ============================================================================
 * Noise-encrypted transport I/O
 * ========================================================================== */

/* Send a Noise transport frame: [0x04][len_hi][len_lo][encrypted_data+MAC] */
static int noise_send(microlink_t *ml, ml_noise_state_t *noise,
                        const uint8_t *plaintext, size_t pt_len) {
    size_t ct_len = pt_len + 16;  /* ciphertext + 16-byte MAC */
    uint8_t *frame = ml_psram_malloc(3 + ct_len);
    if (!frame) return -1;

    frame[0] = 0x04;  /* Transport data frame type */
    frame[1] = (ct_len >> 8) & 0xFF;
    frame[2] = ct_len & 0xFF;

    if (ml_noise_encrypt(noise->tx_key, noise->tx_nonce,
                          NULL, 0,
                          plaintext, pt_len,
                          frame + 3) != ESP_OK) {
        free(frame);
        return -1;
    }
    noise->tx_nonce++;

    int ret = coord_send(ml, frame, 3 + ct_len);
    free(frame);
    return ret;
}

/* Receive and decrypt a Noise transport frame.
 * Returns the plaintext length (>= 0), COORD_RECV_IDLE when nothing was consumed
 * (receive timeout, the stream is still aligned), or COORD_RECV_FATAL: the
 * connection is unusable and must be dropped. */
static int noise_recv(microlink_t *ml, ml_noise_state_t *noise,
                        uint8_t *plaintext, size_t max_len) {
    /* Read 3-byte frame header */
    uint8_t hdr[3];
    int r = coord_recv(ml, hdr, 3);
    if (r < 0) return r;

    /* From here on bytes are consumed: every failure leaves the stream misaligned. */
    if (hdr[0] != 0x04) {
        ESP_LOGE(TAG, "Unexpected Noise frame type: 0x%02x", hdr[0]);
        return COORD_RECV_FATAL;
    }

    uint16_t ct_len = (hdr[1] << 8) | hdr[2];
    if (ct_len < 16) return COORD_RECV_FATAL;
    size_t pt_len = ct_len - 16;
    if (pt_len > max_len) {
        ESP_LOGE(TAG, "Noise frame too large: %d > %d", (int)pt_len, (int)max_len);
        return COORD_RECV_FATAL;
    }

    uint8_t *ciphertext = ml_psram_malloc(ct_len);
    if (!ciphertext) return COORD_RECV_FATAL;

    /* Header already consumed: the payload read MUST complete. A timeout before its
     * first byte is retried; a partial payload is fatal (coord_recv says so). */
    int payload_retries = 0;
    while ((r = coord_recv(ml, ciphertext, ct_len)) == COORD_RECV_IDLE) {
        if (++payload_retries > 300) break;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (r < 0) {
        ESP_LOGE(TAG, "noise_recv payload failed: ct_len=%d retries=%d",
                 ct_len, payload_retries);
        free(ciphertext);
        return COORD_RECV_FATAL;
    }

    if (ml_noise_decrypt(noise->rx_key, noise->rx_nonce,
                          NULL, 0,
                          ciphertext, ct_len,
                          plaintext) != ESP_OK) {
        ESP_LOGE(TAG, "Noise decrypt failed (nonce=%llu)", (unsigned long long)noise->rx_nonce);
        free(ciphertext);
        return COORD_RECV_FATAL;
    }
    noise->rx_nonce++;

    free(ciphertext);
    return (int)pt_len;
}

/* ============================================================================
 * State: DNS_RESOLVE + TCP_CONNECT
 * ========================================================================== */

static int do_tcp_connect(microlink_t *ml) {
    int64_t t_start = esp_timer_get_time();

    ESP_LOGI(TAG, "Resolving %s...", CTRL_HOST(ml));

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;

    if (ml_getaddrinfo(CTRL_HOST(ml), "80", &hints, &res) != 0 || !res) {
        ESP_LOGE(TAG, "DNS resolve failed for %s", CTRL_HOST(ml));
        return -1;
    }

    int64_t t_dns = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DNS resolve: %lld ms", (t_dns - t_start) / 1000);

    int sock = ml_socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ml_freeaddrinfo(res);
        ESP_LOGE(TAG, "Socket creation failed");
        return -1;
    }

    /* Socket timeouts */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* TCP keepalive (critical for NAT traversal) */
    int keepalive = 1;
    int keepidle = 25;
    int keepintvl = 10;
    int keepcnt = 3;
    ml_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    ml_setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    ml_setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    ml_setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    ESP_LOGI(TAG, "Connecting to %s:80...", CTRL_HOST(ml));

    if (ml_connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        ESP_LOGE(TAG, "TCP connect failed: %d", errno);
        ml_close_sock(sock);
        ml_freeaddrinfo(res);
        return -1;
    }
    ml_freeaddrinfo(res);

    int64_t t_tcp = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] TCP connect: %lld ms (total: %lld ms)",
             (t_tcp - t_dns) / 1000, (t_tcp - t_start) / 1000);

    ml->coord_sock = sock;
    return 0;
}

/* ============================================================================
 * State: NOISE_HANDSHAKE (HTTP/1.1 Upgrade with Noise msg1)
 * ========================================================================== */

/* Server proactive data (stored between handshake and H2 preface) */
static uint8_t *s_server_extra_data = NULL;
static int s_server_extra_data_len = 0;

static int do_noise_handshake(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_noise_start = esp_timer_get_time();

    /* Initialize Noise state with our machine key and Tailscale's server key */
    ml_noise_init(noise,
                   ml->machine_private_key, ml->machine_public_key,
                   NULL);  /* NULL = use default Tailscale server key */

    /* Build Noise message 1 (101 bytes) */
    uint8_t msg1[128];
    size_t msg1_len = 0;
    if (ml_noise_write_msg1(noise, msg1, &msg1_len) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to build Noise msg1");
        return -1;
    }

    /* Base64 encode msg1 for HTTP header */
    char msg1_b64[256];
    size_t b64_len = 0;
    mbedtls_base64_encode((unsigned char *)msg1_b64, sizeof(msg1_b64), &b64_len,
                           msg1, msg1_len);
    msg1_b64[b64_len] = '\0';

    /* Send HTTP/1.1 Upgrade request with Noise msg1 in header */
    char *http_req = ml_psram_malloc(512 + b64_len);
    if (!http_req) return -1;

    int req_len = snprintf(http_req, 512 + b64_len,
        "POST /ts2021 HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: tailscale-control-protocol\r\n"
        "Connection: Upgrade\r\n"
        "User-Agent: Tailscale\r\n"
        "X-Tailscale-Handshake: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        CTRL_HOST(ml), msg1_b64);

    ESP_LOGI(TAG, "Sending Noise handshake (msg1=%d bytes, b64=%d chars)", (int)msg1_len, (int)b64_len);

    if (coord_send(ml, (uint8_t *)http_req, req_len) < 0) {
        free(http_req);
        return -1;
    }
    free(http_req);

    /* Read HTTP response - use large recv() because server often sends
     * HTTP 101 headers + Noise msg2 + proactive frames in the same TCP segment */
    uint8_t *resp = ml_psram_malloc(2048);
    if (!resp) return -1;

    int total = ml_recv(ml->coord_sock, resp, 2047, 0);
    if (total <= 0) {
        ESP_LOGE(TAG, "Handshake recv failed: %d (errno=%d)", total, errno);
        free(resp);
        return -1;
    }
    resp[total] = '\0';

    ESP_LOGI(TAG, "HTTP response received: %d bytes", total);

    /* Verify 101 Switching Protocols */
    if (strstr((char *)resp, "101") == NULL) {
        ESP_LOGE(TAG, "Noise upgrade rejected: %.12s", resp);   /* status line only */
        free(resp);
        return -1;
    }
    ESP_LOGI(TAG, "HTTP 101 received, looking for Noise msg2...");

    /* Find end of HTTP headers */
    uint8_t *body_start = (uint8_t *)strstr((char *)resp, "\r\n\r\n");
    if (!body_start) {
        ESP_LOGE(TAG, "No header terminator found");
        free(resp);
        return -1;
    }
    body_start += 4; /* Skip past \r\n\r\n */

    int body_len = total - (body_start - resp);
    ESP_LOGI(TAG, "Body after HTTP headers: %d bytes", body_len);

    /* Copy entire body to working buffer (may contain msg2 + extra frames) */
    uint8_t *body_buf = NULL;
    int body_buf_len = 0;

    if (body_len > 0) {
        body_buf = ml_psram_malloc(body_len);
        if (body_buf) {
            memcpy(body_buf, body_start, body_len);
            body_buf_len = body_len;
        }
    }
    free(resp);

    /* Ensure we have at least the 3-byte Noise frame header */
    if (body_buf_len < 3) {
        ESP_LOGI(TAG, "Reading Noise msg2 header from socket (have %d bytes)...", body_buf_len);
        /* Need to read from socket - allocate buffer if not yet */
        if (!body_buf) {
            body_buf = ml_psram_malloc(512);
            if (!body_buf) return -1;
        }
        if (coord_recv(ml, body_buf + body_buf_len, 3 - body_buf_len) < 0) {
            ESP_LOGE(TAG, "Failed to read Noise msg2 header");
            free(body_buf);
            return -1;
        }
        body_buf_len = 3;
    }

    /* Parse 3-byte Noise frame header */
    uint8_t msg_type = body_buf[0];
    uint16_t payload_len = (body_buf[1] << 8) | body_buf[2];

    ESP_LOGI(TAG, "Noise frame: type=0x%02x, payload_len=%d", msg_type, payload_len);

    if (msg_type != 0x02) {
        ESP_LOGE(TAG, "Unexpected Noise msg type: 0x%02x (expected 0x02)", msg_type);
        free(body_buf);
        return -1;
    }

    int msg2_total = 3 + payload_len;  /* Total msg2 frame size */

    /* Read remaining msg2 payload bytes from socket if needed */
    if (body_buf_len < msg2_total) {
        ESP_LOGI(TAG, "Reading remaining msg2 payload: have %d, need %d", body_buf_len, msg2_total);
        /* Grow buffer if needed */
        uint8_t *tmp = ml_psram_malloc(msg2_total + 512);
        if (!tmp) { free(body_buf); return -1; }
        memcpy(tmp, body_buf, body_buf_len);
        free(body_buf);
        body_buf = tmp;

        if (coord_recv(ml, body_buf + body_buf_len, msg2_total - body_buf_len) < 0) {
            ESP_LOGE(TAG, "Failed to read Noise msg2 payload");
            free(body_buf);
            return -1;
        }
        body_buf_len = msg2_total;
    }

    ESP_LOGI(TAG, "Noise msg2 complete: %d bytes (payload=%d)", msg2_total, payload_len);

    /* Strip 3-byte header, pass raw payload to noise processing */
    if (ml_noise_read_msg2(noise, body_buf + 3, payload_len) != ESP_OK) {
        ESP_LOGE(TAG, "Noise msg2 processing failed");
        free(body_buf);
        return -1;
    }

    int64_t t_noise_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] Noise handshake: %lld ms", (t_noise_done - t_noise_start) / 1000);
    ESP_LOGI(TAG, "Noise handshake complete, transport keys derived");

    /* Save extra data after msg2 (proactive server transport frames)
     * Server sends these immediately after handshake - each one increments
     * server's tx_nonce. We must process them to keep nonces in sync.
     * (Matches v1 g_server_extra_data logic)
     *
     * On fast connections (WiFi), the proactive frames often arrive in
     * the same TCP segment as the HTTP 101 + msg2. On slow connections
     * (cellular PPP), they arrive in separate TCP segments. We must
     * read from the socket if they weren't in the initial buffer. */
    int extra_len = body_buf_len - msg2_total;
    uint8_t *extra_data = NULL;

    if (extra_len > 0) {
        /* Fast path: proactive frames were in the initial recv buffer */
        ESP_LOGI(TAG, "Found %d bytes of extra data after msg2 (proactive frames)", extra_len);
        extra_data = ml_psram_malloc(extra_len);
        if (extra_data) {
            memcpy(extra_data, body_buf + msg2_total, extra_len);
        }
    } else {
        /* Slow path: proactive frames arrive in subsequent TCP segments.
         * Set a short recv timeout and read them from the socket.
         * Server sends EarlyNoise immediately after msg2, so they should
         * arrive within a few hundred ms even on slow cellular links. */
        ESP_LOGI(TAG, "No extra data in initial buffer, reading proactive frames from socket...");
        struct timeval short_tv = { .tv_sec = 2, .tv_usec = 0 };
        ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_RCVTIMEO, &short_tv, sizeof(short_tv));

        extra_data = ml_psram_malloc(1024);
        if (extra_data) {
            int n = ml_recv(ml->coord_sock, extra_data, 1024, 0);
            if (n > 0) {
                extra_len = n;
                ESP_LOGI(TAG, "Read %d bytes of proactive frames from socket", extra_len);
            } else {
                ESP_LOGI(TAG, "No proactive frames from server (n=%d errno=%d)", n, errno);
                free(extra_data);
                extra_data = NULL;
                extra_len = 0;
            }
        }

        /* Restore normal recv timeout */
        struct timeval normal_tv = { .tv_sec = 60, .tv_usec = 0 };
        ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_RCVTIMEO, &normal_tv, sizeof(normal_tv));
    }

    if (extra_data && extra_len > 0) {
        /* Count proactive transport frames */
        int offset = 0;
        int frame_count = 0;
        while (offset + 3 <= extra_len) {
            uint8_t ft = extra_data[offset];
            uint16_t fl = (extra_data[offset + 1] << 8) | extra_data[offset + 2];
            if (offset + 3 + fl > extra_len) {
                ESP_LOGW(TAG, "Incomplete proactive frame at offset %d", offset);
                break;
            }
            ESP_LOGI(TAG, "Proactive frame %d: type=0x%02x, len=%u", frame_count, ft, fl);
            frame_count++;
            offset += 3 + fl;
        }
        ESP_LOGI(TAG, "Server sent %d proactive transport frames", frame_count);

        /* Store for processing after handshake */
        if (s_server_extra_data) free(s_server_extra_data);
        s_server_extra_data = extra_data;
        s_server_extra_data_len = extra_len;
    } else {
        if (extra_data) free(extra_data);
    }

    free(body_buf);
    return 0;
}

/* ============================================================================
 * Process proactive server frames sent after Noise handshake
 * Copied from v1: decrypt EarlyNoise (frame 0) to get nodeKeyChallenge,
 * then count all frames and set rx_nonce = total count.
 * Frames 1-3 may not decrypt with any nonce/key combo (v1 observation).
 * ========================================================================== */

static void process_proactive_frames(microlink_t *ml, ml_noise_state_t *noise) {
    if (!s_server_extra_data || s_server_extra_data_len <= 0) {
        return;
    }

    ESP_LOGI(TAG, "Processing %d bytes of server proactive data", s_server_extra_data_len);
    s_has_node_key_challenge = false;

    /* Decrypt ALL proactive frames and accumulate plaintext.
     * EarlyNoise content (magic + length + JSON) is split across
     * multiple Noise transport frames:
     *   Frame 0: \xff\xff\xffTS (5 bytes magic)
     *   Frame 1: 4 bytes (big-endian JSON length)
     *   Frame 2: ~95 bytes (JSON with nodeKeyChallenge)
     *   Frame 3: H2 SETTINGS (optional) */
    uint8_t *combined = ml_psram_malloc(1024);
    size_t combined_len = 0;
    int offset = 0;
    int frame_count = 0;
    uint64_t nonce = 0;

    while (offset + 3 <= s_server_extra_data_len) {
        uint8_t ft = s_server_extra_data[offset];
        uint16_t fl = (s_server_extra_data[offset + 1] << 8) | s_server_extra_data[offset + 2];

        if (offset + 3 + fl > s_server_extra_data_len) break;

        ESP_LOGI(TAG, "Proactive frame %d: type=0x%02x, len=%u", frame_count, ft, fl);

        if (ft == 0x04 && fl >= ML_NOISE_MAC_LEN && combined) {
            size_t pt_len = fl - ML_NOISE_MAC_LEN;
            uint8_t *plaintext = ml_psram_malloc(pt_len + 1);

            if (plaintext) {
                esp_err_t ret = ml_noise_decrypt(noise->rx_key, nonce,
                                                  NULL, 0,
                                                  s_server_extra_data + offset + 3, fl,
                                                  plaintext);
                if (ret == ESP_OK) {
                    ESP_LOGI(TAG, "  Decrypted frame %d: %d bytes (nonce=%d)",
                             frame_count, (int)pt_len, (int)nonce);
                    if (combined_len + pt_len < 1024) {
                        memcpy(combined + combined_len, plaintext, pt_len);
                        combined_len += pt_len;
                    }
                } else {
                    ESP_LOGW(TAG, "  Frame %d decrypt failed (nonce=%d)", frame_count, (int)nonce);
                }
                free(plaintext);
            }
        }

        nonce++;
        frame_count++;
        offset += 3 + fl;
    }

    ESP_LOGI(TAG, "Decrypted %d bytes from %d proactive frames", (int)combined_len, frame_count);

    /* Search combined plaintext for nodeKeyChallenge JSON */
    if (combined && combined_len > 0) {
        combined[combined_len < 1024 ? combined_len : 1023] = '\0';

        /* Find JSON start (skip magic + length prefix) */
        char *json_start = NULL;
        for (int i = 0; i < (int)combined_len; i++) {
            if (combined[i] == '{') {
                json_start = (char *)combined + i;
                break;
            }
        }

        if (json_start) {
            ESP_LOGI(TAG, "EarlyNoise payload present");
            cJSON *early_json = cJSON_Parse(json_start);
            if (early_json) {
                cJSON *challenge = cJSON_GetObjectItem(early_json, "nodeKeyChallenge");
                if (challenge && cJSON_IsString(challenge)) {
                    const char *chal_str = challenge->valuestring;
                    ESP_LOGI(TAG, "Found nodeKeyChallenge");

                    /* Parse "chalpub:hex..." format (v1 lines 1402-1424) */
                    if (strncmp(chal_str, "chalpub:", 8) == 0) {
                        const char *hex = chal_str + 8;
                        if (strlen(hex) >= 64) {
                            hex_to_bytes(hex, s_node_key_challenge, 32);
                            s_has_node_key_challenge = true;
                            ESP_LOGI(TAG, "NodeKeyChallenge decoded (32 bytes)");
                        }
                    }
                }
                cJSON_Delete(early_json);
            }
        }
    }
    if (combined) free(combined);

    /* Set rx_nonce to skip all proactive frames */
    ESP_LOGI(TAG, "Setting rx_nonce=%d (skipping %d proactive frames)", frame_count, frame_count);
    noise->rx_nonce = frame_count;

    free(s_server_extra_data);
    s_server_extra_data = NULL;
    s_server_extra_data_len = 0;
}

/* ============================================================================
 * State: H2_PREFACE - Send HTTP/2 connection preface (Noise-encrypted)
 * ========================================================================== */

static int do_h2_preface(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_h2_start = esp_timer_get_time();

    /* Build H2 preface (24+6=30) + SETTINGS with INITIAL_WINDOW_SIZE (9+6=15)
     * + SETTINGS_ACK (9) + connection-level WINDOW_UPDATE (13) = 67 bytes */
    uint8_t h2_init[128];
    int pos = 0;

    int preface_len = ml_h2_build_preface(h2_init, sizeof(h2_init));
    if (preface_len < 0) return -1;
    pos = preface_len;

    int ack_len = ml_h2_build_settings_ack(h2_init + pos, sizeof(h2_init) - pos);
    if (ack_len < 0) return -1;
    pos += ack_len;

    /* Connection-level WINDOW_UPDATE (stream 0) to expand the connection window
     * beyond the 65535 default. SETTINGS INITIAL_WINDOW_SIZE only sets per-stream
     * window; the connection-level window starts at 65535 and must be explicitly
     * expanded with WINDOW_UPDATE on stream 0. */
    uint32_t conn_window_delta = ML_H2_BUFFER_SIZE - 65535;
    if (conn_window_delta > 0) {
        int wu_len = ml_h2_build_window_update(h2_init + pos, sizeof(h2_init) - pos,
                                                0, conn_window_delta);
        if (wu_len > 0) pos += wu_len;
    }

    /* Encrypt and send as one Noise frame */
    if (noise_send(ml, noise, h2_init, pos) < 0) {
        ESP_LOGE(TAG, "Failed to send H2 preface");
        return -1;
    }

    ESP_LOGI(TAG, "H2 preface sent (%d bytes, conn window=%luKB)",
             pos, (unsigned long)(ML_H2_BUFFER_SIZE / 1024));

    /* Read and process server's response (SETTINGS, SETTINGS_ACK, WINDOW_UPDATE, etc.) */
    uint8_t recv_buf[4096];
    int recv_len = noise_recv(ml, noise, recv_buf, sizeof(recv_buf));
    if (recv_len < 0) {
        ESP_LOGW(TAG, "No immediate H2 response from server (may come later)");
        /* Not fatal - server may send its frames later */
    } else {
        ESP_LOGI(TAG, "Server H2 response: %d bytes", recv_len);
    }

    int64_t t_h2_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] H2 preface: %lld ms", (t_h2_done - t_h2_start) / 1000);

    return 0;
}

/* ============================================================================
 * State: REGISTER - RegisterRequest / RegisterResponse
 *
 * Wire format and response classification live in ml_register.c (pure, host
 * testable). This section owns the transport: one request on an H2 stream, a
 * response collected from Noise frames, typed errors instead of "success".
 *
 * Nothing in here logs a response body, an AuthURL or a login name: only
 * states, sizes and booleans.
 * ========================================================================== */

/* Inputs of one register exchange. */
typedef struct {
    uint32_t stream_id;             /* H2 client stream: odd and increasing per connection */
    const uint8_t *node_priv;       /* key being registered (challenge response) */
    const uint8_t *node_pub;
    const uint8_t *old_node_pub;    /* OldNodeKey, NULL if no rotation is pending */
    const char *followup;           /* AuthURL being waited on, NULL for a plain register */
} reg_params_t;

/* The response of one H2 stream, collected incrementally. */
typedef struct {
    uint32_t stream_id;
    uint8_t *h2;            /* H2 bytes not yet consumed (a frame may span Noise frames) */
    size_t h2_len;
    uint8_t *body;          /* DATA payload of stream_id */
    size_t body_len;
    bool end_stream;
    bool reset;             /* RST_STREAM on the stream or GOAWAY on the connection */
    bool overflow;          /* response larger than the baseline read caps */
} reg_stream_t;

static void reg_stream_free(reg_stream_t *rs) {
    if (rs->h2) { ml_register_secure_free(rs->h2, ML_REG_H2_BUF_SIZE); rs->h2 = NULL; }
    if (rs->body) { ml_register_secure_free(rs->body, ML_REG_BODY_BUF_SIZE); rs->body = NULL; }
    rs->h2_len = rs->body_len = 0;
}

static bool reg_stream_init(reg_stream_t *rs, uint32_t stream_id) {
    memset(rs, 0, sizeof(*rs));
    rs->stream_id = stream_id;
    rs->h2 = ml_psram_malloc(ML_REG_H2_BUF_SIZE);
    rs->body = ml_psram_malloc(ML_REG_BODY_BUF_SIZE);
    if (!rs->h2 || !rs->body) {
        if (rs->h2) free(rs->h2);
        if (rs->body) free(rs->body);
        rs->h2 = rs->body = NULL;
        return false;
    }
    return true;
}

/* Consume decrypted H2 bytes: collect DATA for rs->stream_id, answer PING and
 * SETTINGS, replenish the connection window, note END_STREAM / RST_STREAM. */
static void reg_stream_feed(microlink_t *ml, ml_noise_state_t *noise, reg_stream_t *rs,
                            const uint8_t *data, size_t len) {
    if (rs->h2_len + len > ML_REG_H2_BUF_SIZE) { rs->overflow = true; return; }
    memcpy(rs->h2 + rs->h2_len, data, len);
    rs->h2_len += len;

    uint32_t data_bytes = 0;
    size_t pos = 0;
    while (pos + 9 <= rs->h2_len) {
        const uint8_t *f = rs->h2 + pos;
        uint32_t f_len = (f[0] << 16) | (f[1] << 8) | f[2];
        uint8_t f_type = f[3];
        uint8_t f_flags = f[4];
        uint32_t f_stream = ((f[5] & 0x7F) << 24) | (f[6] << 16) | (f[7] << 8) | f[8];

        if (f_len > ML_REG_H2_BUF_SIZE - 9) { rs->overflow = true; break; }
        if (pos + 9 + f_len > rs->h2_len) break;      /* frame continues in the next Noise frame */
        const uint8_t *payload = f + 9;

        switch (f_type) {
        case 0x00:  /* DATA */
            data_bytes += f_len;
            if (f_stream == rs->stream_id) {
                if (rs->body_len + f_len > ML_REG_BODY_BUF_SIZE) {
                    rs->overflow = true;
                } else {
                    memcpy(rs->body + rs->body_len, payload, f_len);
                    rs->body_len += f_len;
                }
                if (f_flags & 0x01) rs->end_stream = true;
            }
            break;
        case 0x01:  /* HEADERS */
            if (f_stream == rs->stream_id && (f_flags & 0x01)) rs->end_stream = true;
            break;
        case 0x03:  /* RST_STREAM */
            if (f_stream == rs->stream_id) rs->reset = true;
            break;
        case 0x07:  /* GOAWAY */
            rs->reset = true;
            break;
        case 0x06:  /* PING: answer with the same payload and ACK */
            if (f_len == 8 && !(f_flags & 0x01)) {
                uint8_t pong[17] = {0x00, 0x00, 0x08, 0x06, 0x01, 0, 0, 0, 0};
                memcpy(pong + 9, payload, 8);
                noise_send(ml, noise, pong, sizeof(pong));
            }
            break;
        case 0x04:  /* SETTINGS */
            if (!(f_flags & 0x01)) {
                uint8_t ack[9] = {0x00, 0x00, 0x00, 0x04, 0x01, 0, 0, 0, 0};
                noise_send(ml, noise, ack, sizeof(ack));
            }
            break;
        default:
            break;
        }
        pos += 9 + f_len;
    }

    if (pos > 0) {
        memmove(rs->h2, rs->h2 + pos, rs->h2_len - pos);
        rs->h2_len -= pos;
    }

    /* Connection-level flow control; the stream's own window is the large
     * INITIAL_WINDOW_SIZE advertised in the H2 preface. */
    if (data_bytes > 0) {
        uint8_t wu[13];
        int wu_len = ml_h2_build_window_update(wu, sizeof(wu), 0, data_bytes);
        if (wu_len > 0) noise_send(ml, noise, wu, wu_len);
    }
}

/* Send one RegisterRequest on p->stream_id. Returns 0 or -1. */
static int register_send(microlink_t *ml, ml_noise_state_t *noise, const reg_params_t *p) {
    int64_t t_start = esp_timer_get_time();

    /* NodeKeyChallengeResponse: prove we own the node private key.
     * X25519(node_private, challenge_public), where the challenge comes from
     * EarlyNoise (v1 lines 1754-1785). */
    char chalresp_str[80];
    const char *chalresp = NULL;
    if (s_has_node_key_challenge) {
        uint8_t challenge_pub_copy[32];
        memcpy(challenge_pub_copy, s_node_key_challenge, 32);
        challenge_pub_copy[31] &= 0x7F;  /* Clear high bit per RFC 7748 */

        uint8_t challenge_response[32];
        x25519(challenge_response, p->node_priv, challenge_pub_copy, 1);

        char chalresp_hex[65];
        bytes_to_hex(challenge_response, 32, chalresp_hex);
        snprintf(chalresp_str, sizeof(chalresp_str), "chalresp:%s", chalresp_hex);
        chalresp = chalresp_str;
    } else {
        ESP_LOGW(TAG, "No nodeKeyChallenge received - registration may fail!");
    }

    /* Auth only when a key is configured (matching v1 behavior). */
    const char *auth_key = (ml->config.auth_key && ml->config.auth_key[0]) ? ml->config.auth_key : NULL;
    if (auth_key) {
        /* [ambient-mod] Diagnostic: confirm that the transmitted key is not
         * truncated. **Log only its length.** The head is the fixed `tskey-`
         * prefix and carries no information; the last four characters are a real
         * secret leak. This line exists only to detect truncation, so one number
         * is sufficient. Keep it: the next suspicion that firmware rewrote the key
         * can be dismissed immediately without repeating the 2026-08-08 investigation. */
        ESP_LOGW(TAG, "AuthKey being sent: len=%d", (int)strlen(auth_key));
    }

    ml_register_req_t req = {
        .capability_version = ML_CTRL_PROTOCOL_VER,
        .node_pub = p->node_pub,
        .old_node_pub = p->old_node_pub,
        .auth_key = auth_key,
        .followup = p->followup,
        .hostname = ml_device_name(ml),
        .preferred_derp = ml->derp_home_region,     /* 0 until a DERP map is known */
        .challenge_response = chalresp,
    };
    char *json_str = ml_register_build_request(&req);
    memset(chalresp_str, 0, sizeof(chalresp_str));
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "RegisterRequest: %d bytes (followup=%d old_key=%d)",
             (int)json_len, p->followup != NULL, p->old_node_pub != NULL);

    /* Build HTTP/2 HEADERS + DATA frames */
    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { ml_register_secure_free(json_str, json_len); return -1; }

    int h2_pos = 0;
    int hdr_len = ml_h2_build_headers_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                              "POST", "/machine/register",
                                              CTRL_HOST(ml), "application/json",
                                              p->stream_id, false);
    if (hdr_len < 0) { ml_register_secure_free(json_str, json_len); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            p->stream_id, true);
    ml_register_secure_free(json_str, json_len);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    int ret = noise_send(ml, noise, h2_buf, h2_pos);
    ml_register_secure_free(h2_buf, json_len + 512);
    if (ret < 0) return -1;

    ESP_LOGI(TAG, "RegisterRequest sent (%d H2 bytes) [TIMING] send: %lld ms",
             h2_pos, (esp_timer_get_time() - t_start) / 1000);
    return 0;
}

/* Blocking read of one complete response. Used for the plain register, which the
 * server answers at once; the open-ended Followup wait never uses this.
 * Returns 0 when the stream ended, -1 with *err set otherwise. */
static int register_read(microlink_t *ml, ml_noise_state_t *noise, reg_stream_t *rs,
                         microlink_error_t *err) {
    for (int i = 0; i < ML_REG_MAX_NOISE_FRAMES && !rs->end_stream && !rs->reset && !rs->overflow; i++) {
        uint8_t *frame_buf = ml_psram_malloc(ML_REG_FRAME_BUF_SIZE);
        if (!frame_buf) { *err = ML_ERR_NETWORK; return -1; }

        int frame_len = noise_recv(ml, noise, frame_buf, ML_REG_FRAME_BUF_SIZE);
        if (frame_len <= 0) {
            ml_register_secure_free(frame_buf, ML_REG_FRAME_BUF_SIZE);
            *err = ML_ERR_NETWORK;    /* receive timeout or connection closed */
            return -1;
        }
        ESP_LOGI(TAG, "RegisterResponse Noise frame %d: %d bytes", i, frame_len);
        reg_stream_feed(ml, noise, rs, frame_buf, frame_len);
        ml_register_secure_free(frame_buf, ML_REG_FRAME_BUF_SIZE);   /* may hold the AuthURL */
    }
    if (rs->overflow) { *err = ML_ERR_PROTOCOL; return -1; }
    if (rs->reset) { *err = ML_ERR_NETWORK; return -1; }
    if (!rs->end_stream) { *err = ML_ERR_PROTOCOL; return -1; }
    return 0;
}

/* Non-blocking step of an open request, in the pattern of poll_map_update():
 * select() for 50 ms, then at most one Noise frame.
 * Returns 0 nothing arrived, 1 progress, 2 response complete, -1 failed (*err set). */
static int register_poll(microlink_t *ml, ml_noise_state_t *noise, reg_stream_t *rs,
                         microlink_error_t *err) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(ml->coord_sock, &readfds);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
    if (ml_select_fds(ml->coord_sock + 1, &readfds, NULL, NULL, &tv) <= 0) return 0;

    /* Short receive timeout: a partial frame must not park the task. */
    struct timeval tv_recv = { .tv_sec = 2, .tv_usec = 0 };
    ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_recv, sizeof(tv_recv));

    uint8_t *frame_buf = ml_psram_malloc(ML_REG_FRAME_BUF_SIZE);
    if (!frame_buf) return 0;

    int frame_len = noise_recv(ml, noise, frame_buf, ML_REG_FRAME_BUF_SIZE);
    if (frame_len < 0) {
        ml_register_secure_free(frame_buf, ML_REG_FRAME_BUF_SIZE);
        if (frame_len == COORD_RECV_IDLE) return 0;      /* nothing consumed: still aligned */
        *err = ML_ERR_NETWORK;                           /* fatal: drop the connection */
        return -1;
    }

    reg_stream_feed(ml, noise, rs, frame_buf, frame_len);
    ml_register_secure_free(frame_buf, ML_REG_FRAME_BUF_SIZE);       /* may hold the AuthURL */

    if (rs->overflow) { *err = ML_ERR_PROTOCOL; return -1; }
    if (rs->reset) { *err = ML_ERR_NETWORK; return -1; }
    return rs->end_stream ? 2 : 1;
}

/* One complete register exchange. Returns 0 with *out classified (any kind,
 * including EMPTY and MALFORMED), or -1 with *err set for transport failures. */
static int register_exchange(microlink_t *ml, ml_noise_state_t *noise, const reg_params_t *p,
                             ml_register_result_t *out, microlink_error_t *err) {
    int64_t t_start = esp_timer_get_time();
    memset(out, 0, sizeof(*out));
    *err = ML_ERR_NETWORK;

    reg_stream_t rs;
    if (!reg_stream_init(&rs, p->stream_id)) return -1;

    int ret = -1;
    if (register_send(ml, noise, p) == 0 && register_read(ml, noise, &rs, err) == 0) {
        ml_register_parse_response(rs.body, rs.body_len, out);
        ESP_LOGI(TAG, "RegisterResponse: %d bytes, kind=%d, auth_url=%d error=%d "
                      "node_key_expired=%d machine_authorized=%d",
                 (int)rs.body_len, (int)out->kind, out->auth_url != NULL, out->error_present,
                 out->node_key_expired, out->machine_authorized);
        ret = 0;
    }
    reg_stream_free(&rs);

    ESP_LOGI(TAG, "[TIMING] Register total: %lld ms", (esp_timer_get_time() - t_start) / 1000);
    return ret;
}

/* HTTP/2 PING with a timestamp payload; keeps the control connection alive. */
static int send_h2_ping(microlink_t *ml, ml_noise_state_t *noise, uint64_t now) {
    uint8_t ping_frame[17] = {0x00, 0x00, 0x08, 0x06, 0x00, 0, 0, 0, 0};
    for (int b = 0; b < 8; b++) ping_frame[9 + b] = (now >> (56 - b * 8)) & 0xFF;
    return noise_send(ml, noise, ping_frame, sizeof(ping_frame));
}

/* Publish a public state. The callback fires for the states a caller acts on;
 * the transient connecting states stay silent as before. */
static void coord_publish_state(microlink_t *ml, microlink_state_t st) {
    microlink_state_t prev = ml->state;
    ml->state = st;
    if (prev == st) return;
    if (st == ML_STATE_NEEDS_LOGIN || st == ML_STATE_NEEDS_MACHINE_AUTH || st == ML_STATE_ERROR) {
        ESP_LOGI(TAG, "State -> %d (error category %d)", (int)st, (int)ml->last_error);
        if (ml->state_cb) ml->state_cb(ml, st, ml->state_cb_data);
    }
}

/* Make a failure terminal: close the connection, record the category, publish ERROR.
 * Retried categories never come here. */
static void coord_fail(microlink_t *ml, ml_noise_state_t *noise, coord_state_t *state,
                       microlink_error_t category) {
    if (ml->coord_sock >= 0) {
        ml_close_sock(ml->coord_sock);
        ml->coord_sock = -1;
    }
    memset(noise, 0, sizeof(*noise));
    ml_set_auth_url(ml, NULL);
    ml->last_error = category;
    coord_publish_state(ml, ML_STATE_ERROR);
    *state = COORD_FAILED;
}

/* ============================================================================
 * State: FETCH_PEERS - Send MapRequest, parse MapResponse
 * ========================================================================== */

/* Priority peer bookkeeping for the home region (ml_netcheck_apply_home). */
static void track_priority_peer(microlink_t *ml, const uint8_t key[32], uint32_t vpn_ip,
                                uint16_t region) {
    ml_netcheck_t *nc = &ml->netcheck;
    memcpy(nc->peer_key, key, 32);
    nc->peer_key_valid = true;
    nc->peer_ip = vpn_ip;
    nc->peer_region = region;
}

static bool is_tracked_peer(const microlink_t *ml, const uint8_t key[32]) {
    return ml->netcheck.peer_key_valid && memcmp(ml->netcheck.peer_key, key, 32) == 0;
}

static void forget_priority_peer(microlink_t *ml) {
    ml->netcheck.peer_key_valid = false;
    ml->netcheck.peer_ip = 0;
    ml->netcheck.peer_region = 0;
}

static void parse_peers_from_map_response(microlink_t *ml, cJSON *root) {
    /* "Peers" is the whole list: a priority peer missing from it is gone. */
    bool full_list = cJSON_IsArray(cJSON_GetObjectItem(root, "Peers"));
    bool priority_seen = false;
    /* Try all field names used by Tailscale (copied from v1 lines 3176-3184):
     *   "Peers"        - Full peer list (initial Stream=false response)
     *   "PeersChanged" - Incremental updates (Stream=true long-poll)
     *   "peers"        - Lowercase fallback */
    cJSON *peers = cJSON_GetObjectItem(root, "Peers");
    if (!peers) {
        peers = cJSON_GetObjectItem(root, "PeersChanged");
        if (peers) ESP_LOGI(TAG, "Using 'PeersChanged' field for peer list");
    }
    if (!peers) {
        peers = cJSON_GetObjectItem(root, "peers");
        if (peers) ESP_LOGI(TAG, "Using 'peers' (lowercase) field for peer list");
    }
    if (!peers || !cJSON_IsArray(peers)) {
        /* Normal for delta updates (PeersRemoved, PeersChangedPatch only) */
        goto check_removed;
    }

    int count = cJSON_GetArraySize(peers);
    ESP_LOGI(TAG, "MapResponse: %d peers", count);

    /* The priority peer is marked on every netmap, so a name set or changed later
     * applies from the next one on (microlink_set_priority_peer_name). */
    char priority_name[ML_DNS_NAME_MAX + 1];
    ml_copy_priority_name(ml, priority_name, sizeof(priority_name));

    cJSON *peer;
    cJSON_ArrayForEach(peer, peers) {
        /* Allocate peer update (freed by wg_mgr after processing) */
        ml_peer_update_t *update = ml_psram_calloc(1, sizeof(ml_peer_update_t));
        if (!update) continue;

        update->action = ML_PEER_ADD;

        /* Hostname */
        cJSON *name = cJSON_GetObjectItem(peer, "Name");
        if (name && name->valuestring && priority_name[0]) {
            update->priority = ml_dns_name_equal(name->valuestring, priority_name);
        }
        if (name && name->valuestring) {
            strncpy(update->hostname, name->valuestring, sizeof(update->hostname) - 1);
            /* Strip trailing dot from FQDN */
            size_t hlen = strlen(update->hostname);
            if (hlen > 0 && update->hostname[hlen - 1] == '.') {
                update->hostname[hlen - 1] = '\0';
            }
        }

        /* NodeKey: "nodekey:HEX..." */
        cJSON *key = cJSON_GetObjectItem(peer, "Key");
        if (key && key->valuestring) {
            const char *hex = key->valuestring;
            if (strncmp(hex, "nodekey:", 8) == 0) hex += 8;
            hex_to_bytes(hex, update->public_key, 32);
        }

        /* DiscoKey: "discokey:HEX..." */
        cJSON *disco = cJSON_GetObjectItem(peer, "DiscoKey");
        if (disco && disco->valuestring) {
            const char *hex = disco->valuestring;
            if (strncmp(hex, "discokey:", 9) == 0) hex += 9;
            hex_to_bytes(hex, update->disco_key, 32);
        }

        /* VPN IP from Addresses */
        cJSON *addresses = cJSON_GetObjectItem(peer, "Addresses");
        if (addresses && cJSON_GetArraySize(addresses) > 0) {
            const char *addr = cJSON_GetArrayItem(addresses, 0)->valuestring;
            if (addr) {
                unsigned a, b, c, d;
                /* Handle CIDR notation (e.g., "100.64.1.2/32") */
                if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    update->vpn_ip = (a << 24) | (b << 16) | (c << 8) | d;
                }
            }
        }

        /* DERP region — try modern HomeDERP (int) first, then legacy DERP string */
        cJSON *peer_home_derp = cJSON_GetObjectItem(peer, "HomeDERP");
        if (peer_home_derp && cJSON_IsNumber(peer_home_derp) && peer_home_derp->valueint > 0) {
            update->derp_region = (uint16_t)peer_home_derp->valueint;
        } else {
            cJSON *derp = cJSON_GetObjectItem(peer, "DERP");
            if (derp && derp->valuestring) {
                /* Format: "127.3.3.40:N" where N is the region number */
                unsigned dr;
                if (sscanf(derp->valuestring, "127.3.3.40:%u", &dr) == 1) {
                    update->derp_region = (uint16_t)dr;
                }
            }
        }

        /* Endpoints */
        cJSON *endpoints = cJSON_GetObjectItem(peer, "Endpoints");
        if (endpoints) {
            int ep_count = 0;
            cJSON *ep;
            cJSON_ArrayForEach(ep, endpoints) {
                if (ep_count >= ML_MAX_ENDPOINTS) break;
                if (ep->valuestring) {
                    unsigned ea, eb, ec, ed, eport;
                    if (sscanf(ep->valuestring, "%u.%u.%u.%u:%u",
                               &ea, &eb, &ec, &ed, &eport) == 5) {
                        update->endpoints[ep_count].ip =
                            (ea << 24) | (eb << 16) | (ec << 8) | ed;
                        update->endpoints[ep_count].port = (uint16_t)eport;
                        update->endpoints[ep_count].is_ipv6 = false;
                        ep_count++;
                    }
                }
            }
            update->endpoint_count = ep_count;
        }

        /* Same rule as wg_mgr's admission: by name, or by CONFIG_ML_PRIORITY_PEER_IP. */
        bool is_priority = update->priority ||
            (ml->config.priority_peer_ip != 0 && update->vpn_ip == ml->config.priority_peer_ip);
        if (is_priority) {
            track_priority_peer(ml, update->public_key, update->vpn_ip, update->derp_region);
            priority_seen = true;
        } else if (is_tracked_peer(ml, update->public_key)) {
            forget_priority_peer(ml);       /* renamed, or the priority name changed */
        }

        /* Hand to the wg_mgr task. Never blocks or drops. wg_mgr takes nothing before
         * ML_EVT_COORD_REGISTERED, so a whole netmap waits here first (see do_fetch_peers
         * for a netmap that is read again before that). */
        ml_peer_updates_push(ml, update);
    }

check_removed:
    if (full_list && !priority_seen) forget_priority_peer(ml);

    /* Handle PeersRemoved — array of nodekey strings (long-poll delta updates) */
    cJSON *removed = cJSON_GetObjectItem(root, "PeersRemoved");
    if (removed && cJSON_IsArray(removed)) {
        int rm_count = cJSON_GetArraySize(removed);
        ESP_LOGI(TAG, "PeersRemoved: %d peers", rm_count);

        cJSON *key_item;
        cJSON_ArrayForEach(key_item, removed) {
            if (!key_item->valuestring) continue;

            ml_peer_update_t *update = ml_psram_calloc(1, sizeof(ml_peer_update_t));
            if (!update) continue;

            update->action = ML_PEER_REMOVE;

            const char *hex = key_item->valuestring;
            if (strncmp(hex, "nodekey:", 8) == 0) hex += 8;
            hex_to_bytes(hex, update->public_key, 32);
            if (is_tracked_peer(ml, update->public_key)) forget_priority_peer(ml);

            ml_peer_updates_push(ml, update);
        }
    }

    /* Handle PeersChangedPatch — lightweight endpoint-only updates */
    cJSON *patches = cJSON_GetObjectItem(root, "PeersChangedPatch");
    if (patches && cJSON_IsObject(patches)) {
        ESP_LOGI(TAG, "PeersChangedPatch: processing lightweight updates");
        cJSON *patch = patches->child;
        while (patch) {
            if (patch->string && cJSON_IsObject(patch)) {
                /* Key is nodekey string, value has optional fields like Endpoints, DERP */
                ml_peer_update_t *update = ml_psram_calloc(1, sizeof(ml_peer_update_t));
                if (update) {
                    update->action = ML_PEER_UPDATE_ENDPOINT;

                    const char *hex = patch->string;
                    if (strncmp(hex, "nodekey:", 8) == 0) hex += 8;
                    hex_to_bytes(hex, update->public_key, 32);

                    /* Parse DERP region if present — try DERPRegion (int) first,
                     * then legacy DERP string */
                    cJSON *patch_derp_region = cJSON_GetObjectItem(patch, "DERPRegion");
                    if (patch_derp_region && cJSON_IsNumber(patch_derp_region) && patch_derp_region->valueint > 0) {
                        update->derp_region = (uint16_t)patch_derp_region->valueint;
                    } else {
                        cJSON *derp = cJSON_GetObjectItem(patch, "DERP");
                        if (derp && derp->valuestring) {
                            unsigned dr;
                            if (sscanf(derp->valuestring, "127.3.3.40:%u", &dr) == 1) {
                                update->derp_region = (uint16_t)dr;
                            }
                        }
                    }

                    if (update->derp_region > 0 && is_tracked_peer(ml, update->public_key)) {
                        ml->netcheck.peer_region = update->derp_region;
                    }

                    /* Parse endpoints if present */
                    cJSON *endpoints = cJSON_GetObjectItem(patch, "Endpoints");
                    if (endpoints) {
                        int ep_count = 0;
                        cJSON *ep;
                        cJSON_ArrayForEach(ep, endpoints) {
                            if (ep_count >= ML_MAX_ENDPOINTS) break;
                            if (ep->valuestring) {
                                unsigned ea, eb, ec, ed, eport;
                                if (sscanf(ep->valuestring, "%u.%u.%u.%u:%u",
                                           &ea, &eb, &ec, &ed, &eport) == 5) {
                                    update->endpoints[ep_count].ip =
                                        (ea << 24) | (eb << 16) | (ec << 8) | ed;
                                    update->endpoints[ep_count].port = (uint16_t)eport;
                                    update->endpoints[ep_count].is_ipv6 = false;
                                    ep_count++;
                                }
                            }
                        }
                        update->endpoint_count = ep_count;
                    }

                    ml_peer_updates_push(ml, update);
                }
            }
            patch = patch->next;
        }
    }

    /* The priority peer's home region is ours while it is in the DERP map; the
     * caller acts on a change (ml_netcheck_take_home_change). */
    ml_netcheck_apply_home(ml);
}

/* Add Endpoints + EndpointTypes arrays to a MapRequest JSON object.
 * Includes: WiFi LAN endpoint (type=Local), STUN IPv4 (type=STUN),
 * STUN IPv6 (type=STUN). Returns number of endpoints added. */
static int add_endpoints_to_json(microlink_t *ml, cJSON *root) {
    int count = 0;
    cJSON *ep_array = cJSON_AddArrayToObject(root, "Endpoints");
    cJSON *et_array = cJSON_AddArrayToObject(root, "EndpointTypes");
    if (!ep_array || !et_array) return 0;

    /* LAN endpoint (WiFi STA) */
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            uint32_t local_ip = ntohl(ip_info.ip.addr);
            char ep_str[32];
            snprintf(ep_str, sizeof(ep_str), "%lu.%lu.%lu.%lu:%u",
                     (unsigned long)((local_ip >> 24) & 0xFF),
                     (unsigned long)((local_ip >> 16) & 0xFF),
                     (unsigned long)((local_ip >> 8) & 0xFF),
                     (unsigned long)(local_ip & 0xFF),
                     ml->disco_local_port);
            cJSON_AddItemToArray(ep_array, cJSON_CreateString(ep_str));
            cJSON_AddItemToArray(et_array, cJSON_CreateNumber(1));  /* EndpointLocal */
            count++;
        }
    }

    /* PPP endpoint (cellular) — use STUN-discovered public IP as our endpoint */
    /* (PPP netif doesn't have a useful local IP for peers — it's behind CGNAT) */

    /* STUN public endpoint (IPv4) */
    if (ml->stun_public_ip != 0) {
        uint32_t pub_ip = ml->stun_public_ip;
        uint16_t pub_port = ml->stun_public_port ? ml->stun_public_port : ml->disco_local_port;
        char ep_str[32];
        snprintf(ep_str, sizeof(ep_str), "%lu.%lu.%lu.%lu:%u",
                 (unsigned long)((pub_ip >> 24) & 0xFF),
                 (unsigned long)((pub_ip >> 16) & 0xFF),
                 (unsigned long)((pub_ip >> 8) & 0xFF),
                 (unsigned long)(pub_ip & 0xFF),
                 pub_port);
        cJSON_AddItemToArray(ep_array, cJSON_CreateString(ep_str));
        cJSON_AddItemToArray(et_array, cJSON_CreateNumber(2));  /* EndpointSTUN */
        count++;
    }

    /* STUN public endpoint (IPv6) — only include if it's a real IPv6 address,
     * not an IPv4-mapped IPv6 (::ffff:x.x.x.x) which is redundant with IPv4. */
    if (ml->stun_has_ipv6) {
        const uint8_t *a = ml->stun_public_ip6;
        /* Check for IPv4-mapped prefix: first 10 bytes zero, bytes 10-11 = 0xff */
        static const uint8_t v4mapped_prefix[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
        bool is_v4mapped = (memcmp(a, v4mapped_prefix, 12) == 0);
        if (!is_v4mapped) {
            uint16_t port6 = ml->stun_public_port6 ? ml->stun_public_port6 : ml->disco_local_port;
            char ep6_str[64];
            snprintf(ep6_str, sizeof(ep6_str),
                     "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                     a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                     a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                     port6);
            cJSON_AddItemToArray(ep_array, cJSON_CreateString(ep6_str));
            cJSON_AddItemToArray(et_array, cJSON_CreateNumber(2));  /* EndpointSTUN */
            count++;
        }
    }

    if (count > 0) {
        ESP_LOGI(TAG, "MapRequest includes %d endpoint(s)", count);
    }
    return count;
}

/* Self-node fields that drive public state (DESIGN section 7.3): MagicDNS name,
 * machine approval and key expiry. `Node` is in every full netmap and, in a delta
 * update, whenever the self node changed. MachineAuthorized is omitted when false. */
static void apply_self_node(microlink_t *ml, cJSON *node, bool read_expired) {
    cJSON *name = cJSON_GetObjectItem(node, "Name");
    if (cJSON_IsString(name) && name->valuestring) ml_set_self_fqdn(ml, name->valuestring);
    ml->machine_authorized = cJSON_IsTrue(cJSON_GetObjectItem(node, "MachineAuthorized"));
    ml->machine_auth_known = true;
    if (read_expired) ml->key_expired = cJSON_IsTrue(cJSON_GetObjectItem(node, "Expired"));
}

/* Parse MapResponse.DERPMap (full netmap or delta) into ml->derp_regions, then let
 * netcheck validate the home region and schedule a full measurement. */
static void parse_derp_map(microlink_t *ml, cJSON *map_json) {
    cJSON *derp_map = cJSON_GetObjectItem(map_json, "DERPMap");
    if (derp_map) {
        cJSON *regions = cJSON_GetObjectItem(derp_map, "Regions");
        if (regions && cJSON_GetArraySize(regions) == 0) {
            /* No region to use: keep the previous map and home region. */
            ESP_LOGW(TAG, "DERPMap without regions ignored");
            regions = NULL;
        }
        if (regions) {
            /* Keep resolved STUN addresses of nodes that did not change (no repeat DNS). */
            ml_derp_region_t *old = ml_psram_malloc(sizeof(ml->derp_regions));
            int old_count = ml->derp_region_count;
            if (old) memcpy(old, ml->derp_regions, sizeof(ml->derp_regions));
            ml->derp_region_count = 0;
            cJSON *region_obj;
            cJSON_ArrayForEach(region_obj, regions) {
                if (ml->derp_region_count >= ML_MAX_DERP_REGIONS) break;
                ml_derp_region_t *r = &ml->derp_regions[ml->derp_region_count];
                memset(r, 0, sizeof(*r));

                cJSON *rid = cJSON_GetObjectItem(region_obj, "RegionID");
                if (rid) r->region_id = (uint16_t)rid->valuedouble;

                cJSON *rcode = cJSON_GetObjectItem(region_obj, "RegionCode");
                if (rcode && rcode->valuestring) {
                    strncpy(r->code, rcode->valuestring, sizeof(r->code) - 1);
                }

                cJSON *avoid = cJSON_GetObjectItem(region_obj, "Avoid");
                if (avoid && cJSON_IsTrue(avoid)) r->avoid = true;
                r->no_measure = cJSON_IsTrue(cJSON_GetObjectItem(region_obj, "NoMeasureNoHome"));
                /* A region whose DERP connects failed stays excluded across maps. */
                for (int k = 0; old && k < old_count; k++) {
                    if (old[k].region_id == r->region_id) r->derp_failed = old[k].derp_failed;
                }

                /* Parse nodes */
                cJSON *nodes = cJSON_GetObjectItem(region_obj, "Nodes");
                if (nodes) {
                    cJSON *node_obj;
                    cJSON_ArrayForEach(node_obj, nodes) {
                        if (r->node_count >= ML_MAX_DERP_NODES) break;
                        ml_derp_node_t *n = &r->nodes[r->node_count];
                        memset(n, 0, sizeof(*n));

                        cJSON *hn = cJSON_GetObjectItem(node_obj, "HostName");
                        if (hn && hn->valuestring) {
                            strncpy(n->hostname, hn->valuestring, sizeof(n->hostname) - 1);
                        }

                        cJSON *ip4 = cJSON_GetObjectItem(node_obj, "IPv4");
                        if (ip4 && ip4->valuestring) {
                            strncpy(n->ipv4, ip4->valuestring, sizeof(n->ipv4) - 1);
                        }

                        cJSON *ip6 = cJSON_GetObjectItem(node_obj, "IPv6");
                        if (ip6 && ip6->valuestring) {
                            strncpy(n->ipv6, ip6->valuestring, sizeof(n->ipv6) - 1);
                        }

                        cJSON *sp = cJSON_GetObjectItem(node_obj, "STUNPort");
                        if (cJSON_IsNumber(sp)) n->stun_port = sp->valueint;   /* -1: STUN off */

                        cJSON *dp = cJSON_GetObjectItem(node_obj, "DERPPort");
                        if (dp) n->derp_port = (uint16_t)dp->valuedouble;

                        cJSON *so = cJSON_GetObjectItem(node_obj, "STUNOnly");
                        if (so && cJSON_IsTrue(so)) n->stun_only = true;
                        if (old) ml_nc_keep_resolved(n, r->region_id, old, old_count);

                        r->node_count++;
                    }
                }

                ESP_LOGI(TAG, "  DERP region %d: %d nodes%s",
                         r->region_id, r->node_count,
                         (r->avoid || r->no_measure) ? " [not measured]" : "");

                ml->derp_region_count++;
            }
            free(old);
            ESP_LOGI(TAG, "DERPMap: parsed %d regions", ml->derp_region_count);
            ml_netcheck_on_derp_map(ml);   /* a lost home region is reported by the next round */
        }
    }

}

static int do_fetch_peers(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_map_start = esp_timer_get_time();

    /* Build MapRequest JSON */
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "Version", ML_CTRL_PROTOCOL_VER);

    char key_hex[65];
    char key_str[80];
    bytes_to_hex(ml->wg_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "nodekey:%s", key_hex);
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    /* DiscoKey */
    bytes_to_hex(ml->disco_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "discokey:%s", key_hex);
    cJSON_AddStringToObject(root, "DiscoKey", key_str);

    /* Stream=false for initial fetch */
    cJSON_AddBoolToObject(root, "Stream", false);
    cJSON_AddBoolToObject(root, "KeepAlive", true);
    cJSON_AddStringToObject(root, "Compress", "");  /* Disable compression */

    /* Hostinfo */
    cJSON *hostinfo = cJSON_CreateObject();
    const char *dev_name = (ml->config.device_name && ml->config.device_name[0]) ? ml->config.device_name : microlink_default_device_name();
    cJSON_AddStringToObject(hostinfo, "Hostname", dev_name);
    cJSON_AddStringToObject(hostinfo, "OS", "linux");
    cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
    cJSON_AddStringToObject(hostinfo, "GoArch", "arm");
    cJSON_AddItemToObject(root, "Hostinfo", hostinfo);

    /* NetInfo: tell control plane our preferred DERP region and NAT type.
     * MUST be inside Hostinfo — the control plane reads Hostinfo.NetInfo.PreferredDERP
     * to populate Node.HomeDERP for other peers. */
    cJSON *netinfo = cJSON_CreateObject();
    if (netinfo) {
        cJSON_AddNumberToObject(netinfo, "PreferredDERP", ml->derp_home_region);
        if (ml->stun_nat_checked) {
            cJSON_AddBoolToObject(netinfo, "MappingVariesByDestIP", ml->nat_mapping_varies);
        }
        cJSON_AddItemToObject(hostinfo, "NetInfo", netinfo);
    }

    /* Include endpoints if STUN has already completed (Stream=false →
     * control plane processes these, unlike Stream=true with Version >= 68) */
    add_endpoints_to_json(ml, root);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "MapRequest: %d bytes (Stream=false)", (int)json_len);

    /* Build H2 HEADERS + DATA, stream ID 3 (stream 1 was register) */
    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { free(json_str); return -1; }

    int h2_pos = 0;

    int hdr_len = ml_h2_build_headers_frame(h2_buf + h2_pos, json_len + 512,
                                              "POST", "/machine/map",
                                              CTRL_HOST(ml), "application/json",
                                              3, false);
    if (hdr_len < 0) { free(json_str); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            3, true);
    free(json_str);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    if (noise_send(ml, noise, h2_buf, h2_pos) < 0) {
        free(h2_buf);
        return -1;
    }
    free(h2_buf);

    int64_t t_map_sent = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] MapRequest send: %lld ms", (t_map_sent - t_map_start) / 1000);

    /* Read MapResponse - accumulate ALL decrypted Noise frames first, then parse H2.
     * This is critical because a single H2 frame can span multiple Noise frames
     * (v1 does the same with h2_buffer).
     * Smart timeout: extend to 60s for large tailnets (300+ peers = 240KB+). */
    uint8_t *h2_recv = ml_psram_malloc(ML_H2_BUFFER_SIZE);  /* 512KB for 300+ peer tailnets */
    if (!h2_recv) return -1;
    size_t h2_total = 0;

    uint8_t *resp_buf = ml_psram_malloc(ML_JSON_BUFFER_SIZE);
    if (!resp_buf) { free(h2_recv); return -1; }
    size_t json_total = 0;

    /* Set extended recv timeout for large MapResponse (60 seconds) */
    struct timeval rcv_tv = { .tv_sec = 60, .tv_usec = 0 };
    ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv));

    uint64_t recv_start_ms = ml_get_time_ms();
    uint64_t last_progress_ms = recv_start_ms;
    size_t window_consumed = 0;

    /* Read all Noise frames and accumulate decrypted H2 data.
     * Scan for H2 END_STREAM flag (0x01) on DATA frames to know when the
     * response is complete — without this, we wait for the full recv timeout
     * (60s) before proceeding, which dominates connection time on cellular. */
    bool got_end_stream = false;
    for (int read_count = 0; read_count < 200; read_count++) {
        uint8_t *frame_buf = ml_psram_malloc(65536);
        if (!frame_buf) break;

        int frame_len = noise_recv(ml, noise, frame_buf, 65536);
        if (frame_len <= 0) {
            free(frame_buf);
            break;
        }

        /* Append decrypted data to h2_recv */
        if (h2_total + frame_len < ML_H2_BUFFER_SIZE) {
            memcpy(h2_recv + h2_total, frame_buf, frame_len);
            h2_total += frame_len;
            window_consumed += frame_len;
        } else {
            ESP_LOGW(TAG, "H2 buffer full at %dKB, truncating", (int)(h2_total / 1024));
            free(frame_buf);
            break;
        }
        free(frame_buf);

        /* Scan newly accumulated data for H2 END_STREAM flag.
         * H2 frame header: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID.
         * DATA frame type=0x00, END_STREAM flag=0x01.
         * We scan from the start each time since frames may span Noise boundaries. */
        size_t scan_pos = 0;
        while (scan_pos + 9 <= h2_total) {
            uint32_t f_len = (h2_recv[scan_pos] << 16) | (h2_recv[scan_pos + 1] << 8) | h2_recv[scan_pos + 2];
            uint8_t f_type = h2_recv[scan_pos + 3];
            uint8_t f_flags = h2_recv[scan_pos + 4];

            if (scan_pos + 9 + f_len > h2_total) break;  /* Incomplete frame */

            if (f_type == 0x00 && (f_flags & 0x01)) {
                /* DATA frame with END_STREAM — response is complete */
                got_end_stream = true;
            }
            scan_pos += 9 + f_len;
        }

        if (got_end_stream) {
            ESP_LOGI(TAG, "H2 END_STREAM detected after %d Noise frames (%dKB, %lums)",
                     read_count + 1, (int)(h2_total / 1024),
                     (unsigned long)(ml_get_time_ms() - recv_start_ms));
            break;
        }

        /* Progress logging every 5 seconds for large responses */
        uint64_t now = ml_get_time_ms();
        if (now - last_progress_ms > 5000) {
            ESP_LOGI(TAG, "MapResponse: received %dKB so far (%d frames, %lums elapsed)",
                     (int)(h2_total / 1024), read_count + 1,
                     (unsigned long)(now - recv_start_ms));
            last_progress_ms = now;
        }

        /* Proactive WINDOW_UPDATE every 32KB to keep server sending.
         * Must update BOTH connection-level (stream 0) AND stream-level (stream 3)
         * windows, otherwise the server stalls when either window exhausts. */
        if (window_consumed >= 32768) {
            uint8_t wu_buf[26];  /* 2 WINDOW_UPDATE frames: 13 bytes each */
            int wu_len = ml_h2_build_window_update(wu_buf, 13, 0, (uint32_t)window_consumed);
            wu_len += ml_h2_build_window_update(wu_buf + wu_len, 13, 3, (uint32_t)window_consumed);
            if (wu_len > 0) {
                noise_send(ml, noise, wu_buf, wu_len);
            }
            window_consumed = 0;
        }
    }

    /* Restore normal recv timeout (5 seconds for long-poll) */
    rcv_tv.tv_sec = 5;
    ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv));

    ESP_LOGI(TAG, "Accumulated %dKB of H2 data from Noise frames (%lums)",
             (int)(h2_total / 1024),
             (unsigned long)(ml_get_time_ms() - recv_start_ms));

    /* Now parse complete H2 frames from accumulated buffer */
    int fpos = 0;
    while (fpos + 9 <= (int)h2_total) {
        uint32_t f_len = (h2_recv[fpos] << 16) | (h2_recv[fpos + 1] << 8) | h2_recv[fpos + 2];
        uint8_t f_type = h2_recv[fpos + 3];
        uint8_t f_flags = h2_recv[fpos + 4];
        uint32_t f_stream = ((h2_recv[fpos + 5] & 0x7F) << 24) |
                            (h2_recv[fpos + 6] << 16) |
                            (h2_recv[fpos + 7] << 8) | h2_recv[fpos + 8];
        fpos += 9;

        ESP_LOGI(TAG, "  H2 frame: type=%d flags=0x%02x len=%lu stream=%lu",
                 f_type, f_flags, (unsigned long)f_len, (unsigned long)f_stream);

        if (fpos + (int)f_len > (int)h2_total) {
            ESP_LOGW(TAG, "  Incomplete H2 frame at end (need %lu, have %d)",
                     (unsigned long)f_len, (int)h2_total - fpos);
            break;
        }

        if (f_type == 0x00 && f_len > 0) {  /* DATA frame */
            if (json_total + f_len < ML_JSON_BUFFER_SIZE) {
                memcpy(resp_buf + json_total, h2_recv + fpos, f_len);
                json_total += f_len;
            }
        }

        fpos += f_len;
    }
    free(h2_recv);

    /* Send connection-level WINDOW_UPDATE to replenish HTTP/2 flow control.
     * Stream 3 is already closed (END_STREAM received), so only update stream 0.
     * Without this, the server's connection-level window exhausts on large responses. */
    if (json_total > 0) {
        uint8_t wu_buf[13];
        int wu_len = ml_h2_build_window_update(wu_buf, 13, 0, (uint32_t)json_total);
        noise_send(ml, noise, wu_buf, wu_len);
        ESP_LOGI(TAG, "Sent H2 WINDOW_UPDATE: %d bytes (connection level)", (int)json_total);
    }

    if (json_total == 0) {
        ESP_LOGW(TAG, "Empty MapResponse");
        free(resp_buf);
        return -1;
    }

    ESP_LOGI(TAG, "MapResponse JSON: %d bytes", (int)json_total);

    /* Check for length prefix (Tailscale binary framing: 4-byte big-endian length before JSON) */
    char *parse_start = (char *)resp_buf;
    size_t parse_len = json_total;

    /* Find the start of JSON - look for '{' in first 8 bytes */
    int json_offset = -1;
    for (int i = 0; i < 8 && i < (int)json_total; i++) {
        if (resp_buf[i] == '{') {
            json_offset = i;
            break;
        }
    }
    if (json_offset > 0) {
        ESP_LOGI(TAG, "JSON starts at offset %d (skipping %d-byte prefix)", json_offset, json_offset);
        parse_start += json_offset;
        parse_len -= json_offset;
    } else if (json_offset < 0) {
        ESP_LOGW(TAG, "No '{' found in first 8 bytes of MapResponse!");
    }

    /* Null-terminate */
    char saved = parse_start[parse_len];
    parse_start[parse_len] = '\0';

    cJSON *map_json = cJSON_Parse(parse_start);
    parse_start[parse_len] = saved;

    if (!map_json) {
        ESP_LOGE(TAG, "MapResponse JSON parse failed");
        free(resp_buf);
        return -1;
    }

    /* Debug: log the top-level field names and types of the MapResponse (from v1
     * lines 3053-3072). Values are never logged: strings such as Domain name the tailnet. */
    {
        ESP_LOGI(TAG, "MapResponse top-level fields:");
        cJSON *field = NULL;
        cJSON_ArrayForEach(field, map_json) {
            if (field->string) {
                if (cJSON_IsArray(field))
                    ESP_LOGI(TAG, "  - %s (array, size=%d)", field->string, cJSON_GetArraySize(field));
                else if (cJSON_IsObject(field))
                    ESP_LOGI(TAG, "  - %s (object)", field->string);
                else if (cJSON_IsString(field))
                    ESP_LOGI(TAG, "  - %s (string)", field->string);
                else if (cJSON_IsNumber(field))
                    ESP_LOGI(TAG, "  - %s (number)", field->string);
                else if (cJSON_IsBool(field))
                    ESP_LOGI(TAG, "  - %s (bool)", field->string);
                else
                    ESP_LOGI(TAG, "  - %s (other)", field->string);
            }
        }
    }

    /* Extract self-node info */
    {
        cJSON *node = cJSON_GetObjectItem(map_json, "Node");
        if (node) {
            /* Extract VPN IP if not already set */
            if (ml->vpn_ip == 0) {
                cJSON *addresses = cJSON_GetObjectItem(node, "Addresses");
                if (addresses && cJSON_GetArraySize(addresses) > 0) {
                    const char *addr = cJSON_GetArrayItem(addresses, 0)->valuestring;
                    if (addr) {
                        unsigned a, b, c, d;
                        if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                            ml->vpn_ip = (a << 24) | (b << 16) | (c << 8) | d;
                            ESP_LOGI(TAG, "Our VPN IP set");
                        }
                    }
                }
            }
            /* The home DERP region is ours to measure (ml_netcheck.c); the server's
             * HomeDERP only echoes the PreferredDERP we sent. */

            /* Parse KeyExpiry (ISO 8601: "YYYY-MM-DDTHH:MM:SSZ") */
            cJSON *key_expiry = cJSON_GetObjectItem(node, "KeyExpiry");
            if (key_expiry && key_expiry->valuestring) {
                int yr, mo, dy, hr, mn, sc;
                if (sscanf(key_expiry->valuestring, "%d-%d-%dT%d:%d:%d",
                           &yr, &mo, &dy, &hr, &mn, &sc) >= 6) {
                    /* Simple epoch calculation (approximate, no leap second) */
                    /* Days from year 1970 */
                    int64_t days = 0;
                    for (int y = 1970; y < yr; y++) {
                        days += (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
                    }
                    static const int mdays[] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
                    for (int m = 1; m < mo; m++) {
                        days += mdays[m];
                        if (m == 2 && (yr % 4 == 0 && (yr % 100 != 0 || yr % 400 == 0))) days++;
                    }
                    days += dy - 1;
                    ml->key_expiry_epoch = days * 86400 + hr * 3600 + mn * 60 + sc;
                    ESP_LOGI(TAG, "Key expiry epoch: %lld", (long long)ml->key_expiry_epoch);
                }
            }

            /* Check Expired flag */
            cJSON *expired = cJSON_GetObjectItem(node, "Expired");
            if (expired && cJSON_IsTrue(expired)) {
                ml->key_expired = true;
                ESP_LOGW(TAG, "Node key is EXPIRED — re-registration needed");
            } else {
                ml->key_expired = false;
            }

            apply_self_node(ml, node, false);
        } else if (ml->interactive) {
            /* Approval and the node's own name come from the self node (DESIGN section
             * 7.3). A full netmap without one cannot be read as "approved". */
            ESP_LOGE(TAG, "MapResponse has no self node");
            ml->last_error = ML_ERR_PROTOCOL;
            cJSON_Delete(map_json);
            free(resp_buf);
            return -1;
        }
    }

    /* Until registration wg_mgr takes nothing, so updates still queued come from an
     * earlier netmap (every reconnect reads the full list again). This one replaces
     * them. Coord is the only producer and the one that sets the bit. */
    if (!(xEventGroupGetBits(ml->events) & ML_EVT_COORD_REGISTERED)) {
        ml_peer_updates_flush(ml);
    }

    /* Parse peers */
    parse_peers_from_map_response(ml, map_json);

    /* DERP map: the home region is checked against it and measured again. */
    parse_derp_map(ml, map_json);

    cJSON_Delete(map_json);
    free(resp_buf);

    int64_t t_map_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] MapResponse recv+parse: %lld ms (total map: %lld ms, %dKB)",
             (t_map_done - t_map_sent) / 1000,
             (t_map_done - t_map_start) / 1000,
             (int)(h2_total / 1024));

    return 0;
}

/* ============================================================================
 * State: LONG_POLL - Start streaming MapRequest + process incremental updates
 * ========================================================================== */

/* Send MapRequest with Stream=true to start long-poll on H2 stream 5 */
static int do_start_long_poll(microlink_t *ml, ml_noise_state_t *noise) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "Version", ML_CTRL_PROTOCOL_VER);

    char key_hex[65], key_str[80];
    bytes_to_hex(ml->wg_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "nodekey:%s", key_hex);
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    bytes_to_hex(ml->disco_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "discokey:%s", key_hex);
    cJSON_AddStringToObject(root, "DiscoKey", key_str);

    /* Hostinfo - REQUIRED by control plane even for Stream=true.
     * V1 includes this; without it, server may not keep us "online". */
    cJSON *hostinfo = cJSON_CreateObject();
    if (hostinfo) {
        const char *dev_name = (ml->config.device_name && ml->config.device_name[0]) ? ml->config.device_name : microlink_default_device_name();
        cJSON_AddStringToObject(hostinfo, "Hostname", dev_name);
        cJSON_AddStringToObject(hostinfo, "OS", "linux");
        cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
        cJSON_AddStringToObject(hostinfo, "GoArch", "arm");
        cJSON_AddItemToObject(root, "Hostinfo", hostinfo);
    }

    /* NetInfo: tell control plane our preferred DERP region and NAT type.
     * MUST be inside Hostinfo — the control plane reads Hostinfo.NetInfo.PreferredDERP
     * to populate Node.HomeDERP for other peers. */
    cJSON *netinfo = cJSON_CreateObject();
    if (netinfo) {
        cJSON_AddNumberToObject(netinfo, "PreferredDERP", ml->derp_home_region);
        if (ml->stun_nat_checked) {
            cJSON_AddBoolToObject(netinfo, "MappingVariesByDestIP", ml->nat_mapping_varies);
        }
        cJSON_AddItemToObject(hostinfo, "NetInfo", netinfo);
    }

    /* Stream=true for long-poll, KeepAlive=true so server sends keepalives
     * (which marks us as "online" on the control plane) */
    cJSON_AddBoolToObject(root, "Stream", true);
    cJSON_AddBoolToObject(root, "KeepAlive", true);
    cJSON_AddStringToObject(root, "Compress", "");    /* Disable compression */
    cJSON_AddBoolToObject(root, "OmitPeers", true);   /* Already have peers */

    /* NOTE: With Version >= 68, the control plane IGNORES Endpoints and
     * Hostinfo in Stream=true MapRequests. Endpoints are sent via separate
     * do_send_endpoint_update() calls (Stream=false, OmitPeers=true). */

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "MapRequest: %d bytes (Stream=true)", (int)json_len);

    /* Build H2 frames on stream ID 5 */
    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { free(json_str); return -1; }

    int h2_pos = 0;
    int hdr_len = ml_h2_build_headers_frame(h2_buf, json_len + 512,
                                              "POST", "/machine/map",
                                              CTRL_HOST(ml), "application/json",
                                              5, false);
    if (hdr_len < 0) { free(json_str); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            5, true);
    free(json_str);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    if (noise_send(ml, noise, h2_buf, h2_pos) < 0) {
        free(h2_buf);
        return -1;
    }
    free(h2_buf);

    ESP_LOGI(TAG, "Streaming MapRequest sent on stream 5");
    return 0;
}

/* Send a "lite" endpoint update to the control plane.
 * This is a non-streaming MapRequest (Stream=false, OmitPeers=true) that
 * only updates our endpoints and hostinfo. Required because Version >= 68
 * means the control plane IGNORES Endpoints in streaming (Stream=true)
 * MapRequests. The reference client uses a dedicated "updateRoutine" for this.
 *
 * Uses H2 stream 7. Response body is discarded (only HTTP status matters).
 * Returns 0 on success, -1 on send failure. */
static int do_send_endpoint_update(microlink_t *ml, ml_noise_state_t *noise, bool netinfo_changed) {
    if (ml->stun_public_ip == 0 && !ml->stun_has_ipv6 && !netinfo_changed) {
        ESP_LOGD(TAG, "No STUN endpoints yet, skipping endpoint update");
        return 0;  /* Nothing to send */
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "Version", ML_CTRL_PROTOCOL_VER);

    char key_hex[65], key_str[80];
    bytes_to_hex(ml->wg_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "nodekey:%s", key_hex);
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    bytes_to_hex(ml->disco_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "discokey:%s", key_hex);
    cJSON_AddStringToObject(root, "DiscoKey", key_str);

    /* Stream=false so control plane PROCESSES our endpoints (Version >= 68) */
    cJSON_AddBoolToObject(root, "Stream", false);
    cJSON_AddBoolToObject(root, "KeepAlive", true);
    /* OmitPeers=true — we don't need peers back, just updating our endpoints */
    cJSON_AddBoolToObject(root, "OmitPeers", true);
    cJSON_AddStringToObject(root, "Compress", "");

    /* Hostinfo (required — control plane reads NetInfo from here) */
    cJSON *hostinfo = cJSON_CreateObject();
    if (hostinfo) {
        const char *dev_name = (ml->config.device_name && ml->config.device_name[0]) ? ml->config.device_name : microlink_default_device_name();
        cJSON_AddStringToObject(hostinfo, "Hostname", dev_name);
        cJSON_AddStringToObject(hostinfo, "OS", "linux");
        cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
        cJSON_AddStringToObject(hostinfo, "GoArch", "arm");
        cJSON_AddItemToObject(root, "Hostinfo", hostinfo);

        cJSON *netinfo = cJSON_CreateObject();
        if (netinfo) {
            cJSON_AddNumberToObject(netinfo, "PreferredDERP", ml->derp_home_region);
            if (ml->stun_nat_checked) {
                cJSON_AddBoolToObject(netinfo, "MappingVariesByDestIP", ml->nat_mapping_varies);
            }
            cJSON_AddItemToObject(hostinfo, "NetInfo", netinfo);
        }
    }

    /* Endpoints + EndpointTypes */
    int ep_count = add_endpoints_to_json(ml, root);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "Endpoint update: %d bytes, %d endpoints (Stream=false, OmitPeers=true)",
             (int)json_len, ep_count);

    /* Use incrementing odd stream IDs (H2 client-initiated = odd).
     * Streams 1, 3, 5 are used by register, fetch peers, and long-poll.
     * Start at 7, increment by 2 for each endpoint update.
     * Reset to 7 on reconnect (h2_next_stream_id initialized in connect). */
    if (ml->h2_next_stream_id < 7) ml->h2_next_stream_id = 7;
    uint32_t sid = ml->h2_next_stream_id;
    ml->h2_next_stream_id += 2;

    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { free(json_str); return -1; }

    int h2_pos = 0;
    int hdr_len = ml_h2_build_headers_frame(h2_buf, json_len + 512,
                                              "POST", "/machine/map",
                                              CTRL_HOST(ml), "application/json",
                                              sid, false);
    if (hdr_len < 0) { free(json_str); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            sid, true);  /* END_STREAM */
    free(json_str);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    if (noise_send(ml, noise, h2_buf, h2_pos) < 0) {
        free(h2_buf);
        ESP_LOGE(TAG, "Failed to send endpoint update");
        return -1;
    }
    free(h2_buf);

    ESP_LOGI(TAG, "Endpoint update sent on H2 stream %lu", (unsigned long)sid);
    /* Response body is discarded — server may send empty response or
     * we'll consume it in the next poll_map_update() iteration.
     * Only the HTTP status code matters (200 = success). */
    return 0;
}

/* Try to read one incremental MapResponse update (non-blocking).
 * Returns 1 for data, 0 for nothing, -1 when the connection is unusable.
 * This reads one Noise frame only. *map_unparsed (optional) is set when that frame
 * ended inside an H2 frame or its stream-5 JSON did not parse: a netmap update was
 * seen but not read, which matters while waiting for machine approval. */
static int poll_map_update(microlink_t *ml, ml_noise_state_t *noise, bool *map_unparsed) {
    /* Use select() to check if data is available before blocking in recv */
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(ml->coord_sock, &readfds);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };  /* 50ms */
    int sel = ml_select_fds(ml->coord_sock + 1, &readfds, NULL, NULL, &tv);
    if (sel <= 0) return 0;  /* No data available or error */

    /* Data available — set short recv timeout for partial frame safety */
    struct timeval tv_recv = { .tv_sec = 2, .tv_usec = 0 };
    ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_recv, sizeof(tv_recv));

    uint8_t *frame_buf = ml_psram_malloc(65536);
    if (!frame_buf) return 0;

    int frame_len = noise_recv(ml, noise, frame_buf, 65536);

    if (frame_len <= 0) {
        free(frame_buf);
        /* Idle (or an empty frame) = no data yet = not an error; fatal = drop the connection */
        return frame_len == COORD_RECV_FATAL ? -1 : 0;
    }

    /* Extract DATA frame payload from H2 frames, track flow control */
    uint8_t *json_data = NULL;
    size_t json_data_len = 0;
    uint32_t total_data_bytes = 0;
    uint32_t data_stream_id = 0;
    int pos = 0;

    while (pos + 9 <= frame_len) {
        uint32_t f_len = (frame_buf[pos] << 16) | (frame_buf[pos + 1] << 8) | frame_buf[pos + 2];
        uint8_t f_type = frame_buf[pos + 3];
        uint8_t f_flags = frame_buf[pos + 4];
        uint32_t f_stream = ((frame_buf[pos + 5] & 0x7F) << 24) | (frame_buf[pos + 6] << 16) |
                             (frame_buf[pos + 7] << 8) | frame_buf[pos + 8];
        pos += 9;

        if (pos + (int)f_len > frame_len) break;     /* frame continues in the next Noise frame */

        if (f_type == 0x00) {  /* DATA frame */
            total_data_bytes += f_len;
            if (f_stream == 5) {
                /* Long-poll MapResponse data (stream 5) — parse as JSON */
                data_stream_id = f_stream;
                if (f_len > 0) {
                    json_data = frame_buf + pos;
                    json_data_len = f_len;
                }
            } else if (f_len > 0) {
                /* Endpoint update response (stream 7+) — discard body */
                ESP_LOGD(TAG, "H2 stream %lu DATA: %lu bytes (discarded)",
                         (unsigned long)f_stream, (unsigned long)f_len);
            }
        } else if (f_type == 0x06 && f_len == 8 && !(f_flags & 0x01)) {
            /* HTTP/2 PING from server — respond with PONG (same payload, ACK flag) */
            uint8_t pong[17];
            pong[0] = 0x00; pong[1] = 0x00; pong[2] = 0x08;
            pong[3] = 0x06; pong[4] = 0x01;
            pong[5] = 0x00; pong[6] = 0x00; pong[7] = 0x00; pong[8] = 0x00;
            memcpy(pong + 9, frame_buf + pos, 8);
            noise_send(ml, noise, pong, sizeof(pong));
            ESP_LOGI(TAG, "Sent HTTP/2 PONG in response to server PING");
        } else if (f_type == 0x04 && !(f_flags & 0x01)) {
            /* HTTP/2 SETTINGS from server — respond with SETTINGS ACK */
            uint8_t settings_ack[9] = {0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00};
            noise_send(ml, noise, settings_ack, sizeof(settings_ack));
        }
        pos += f_len;
    }
    /* Anything left over is an H2 frame cut by the Noise frame boundary: it is dropped
     * here, as it always was, but the caller may need to know. */
    bool cut_frame = pos < frame_len;
    if (cut_frame && map_unparsed) *map_unparsed = true;

    /* Send HTTP/2 WINDOW_UPDATE to replenish flow control after receiving DATA.
     * Without this, the server's send window exhausts and the connection stalls.
     * Must send for BOTH connection-level (stream 0) AND stream-level. (v1 reference) */
    if (total_data_bytes > 0) {
        uint8_t wu_buf[26];  /* 2 WINDOW_UPDATE frames: 13 bytes each */
        /* Connection-level (stream 0) */
        int wu_len = ml_h2_build_window_update(wu_buf, 13, 0, total_data_bytes);
        /* Stream-level */
        if (data_stream_id > 0) {
            wu_len += ml_h2_build_window_update(wu_buf + wu_len, 13,
                                                  data_stream_id, total_data_bytes);
        }
        noise_send(ml, noise, wu_buf, wu_len);
    }

    if (!json_data || json_data_len == 0) {
        /* Keepalive, SETTINGS, or PING frame - not an error */
        free(frame_buf);
        return 1;  /* Got data, reset watchdog */
    }

    /* Skip 4-byte length prefix if present */
    char *parse_start = (char *)json_data;
    size_t parse_len = json_data_len;
    if (parse_len > 4 && parse_start[4] == '{') {
        parse_start += 4;
        parse_len -= 4;
    }

    char saved = parse_start[parse_len];
    parse_start[parse_len] = '\0';

    cJSON *update_json = cJSON_Parse(parse_start);
    parse_start[parse_len] = saved;

    if (!update_json && map_unparsed) *map_unparsed = true;
    if (update_json) {
        ESP_LOGI(TAG, "Long-poll MapResponse update received");

        /* Update VPN IP if present */
        cJSON *node = cJSON_GetObjectItem(update_json, "Node");
        if (node) {
            apply_self_node(ml, node, true);
            cJSON *addresses = cJSON_GetObjectItem(node, "Addresses");
            if (addresses && cJSON_GetArraySize(addresses) > 0) {
                const char *addr = cJSON_GetArrayItem(addresses, 0)->valuestring;
                if (addr) {
                    unsigned a, b, c, d;
                    if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                        uint32_t new_ip = (a << 24) | (b << 16) | (c << 8) | d;
                        if (new_ip != ml->vpn_ip) {
                            ml->vpn_ip = new_ip;
                            ESP_LOGI(TAG, "VPN IP updated via long-poll");
                        }
                    }
                }
            }
        }

        /* Parse peer updates */
        parse_peers_from_map_response(ml, update_json);
        parse_derp_map(ml, update_json);
        cJSON_Delete(update_json);
    }

    free(frame_buf);
    return 1;
}

/* Close the control connection and reset the Noise state; the next pass through
 * STUN_PROBE / TCP_CONNECT starts a fresh handshake. */
static void coord_drop_connection(microlink_t *ml, ml_noise_state_t *noise) {
    if (ml->coord_sock >= 0) {
        ml_close_sock(ml->coord_sock);
        ml->coord_sock = -1;
    }
    memset(noise, 0, sizeof(*noise));
}

/* Open a Followup (the AuthURL being waited on) on the given H2 stream.
 * The request returns when the user has finished at the URL, so the caller
 * polls it with register_poll(). Returns 0 or -1. */
static int followup_open(microlink_t *ml, ml_noise_state_t *noise, reg_stream_t *rs,
                         uint32_t stream_id) {
    size_t n = ml_auth_url_length(ml);
    if (n == 0 || !reg_stream_init(rs, stream_id)) return -1;

    char *url = ml_psram_malloc(n + 1);
    if (!url) { reg_stream_free(rs); return -1; }
    if (ml_auth_url_copy(ml, url, n + 1) != ESP_OK) {
        ml_register_secure_free(url, n + 1);
        reg_stream_free(rs);
        return -1;
    }

    reg_params_t rp = {
        .stream_id = stream_id,
        .node_priv = ml->wg_private_key,
        .node_pub = ml->wg_public_key,
        .old_node_pub = ml->old_node_valid ? ml->old_node_pub : NULL,
        .followup = url,
    };
    int ret = register_send(ml, noise, &rp);
    ml_register_secure_free(url, n + 1);
    if (ret < 0) reg_stream_free(rs);
    return ret;
}

static bool auth_url_equals(microlink_t *ml, const char *url) {
    bool eq;
    portENTER_CRITICAL(&ml->id_lock);
    eq = ml->auth_url && strcmp(ml->auth_url, url) == 0;
    portEXIT_CRITICAL(&ml->id_lock);
    return eq;
}

/* A login URL was issued. Interactive callers wait for the user (COORD_LOGIN_WAIT);
 * a caller that passed an auth key has no way to show the URL, so its key was not
 * accepted. Returns true when the task is now in COORD_LOGIN_WAIT. */
static bool coord_begin_login(microlink_t *ml, ml_noise_state_t *noise, coord_state_t *state,
                              const char *url) {
    if (!ml->interactive) {
        coord_fail(ml, noise, state, ML_ERR_REGISTER_REJECTED);
        return false;
    }
    if (ml_set_auth_url(ml, url) != ESP_OK) {
        /* The URL could not be kept (and the previous one is gone): unusable response, retried. */
        ml->last_error = ML_ERR_PROTOCOL;
        *state = COORD_RECONNECTING;
        return false;
    }
    ml->last_error = ML_ERR_NONE;
    coord_publish_state(ml, ML_STATE_NEEDS_LOGIN);
    *state = COORD_LOGIN_WAIT;
    return true;
}

/* NodeKeyExpired in a register reply (DESIGN section 12). Always ends in ERROR:
 *  - first expiry of this session: store a new node key, keep the machine key, register
 *    it with OldNodeKey so the control plane links the two, then KEY_ROTATED (the keys in
 *    RAM are stale: the caller restarts, for auth-key and interactive callers alike);
 *  - a second expiry in the same session: the rotated key was refused as well, as
 *    direct.go:861-865 does inside one call. The flag is per session, not the persisted
 *    OldNodeKey, so a failed OLD_PUB clear never makes a later expiry terminal. */
static void coord_handle_key_expired(microlink_t *ml, ml_noise_state_t *noise, coord_state_t *state) {
    if (ml->rotated_this_session) {
        coord_fail(ml, noise, state, ML_ERR_NODE_KEY_EXPIRED);
        return;
    }
    uint8_t new_priv[32], new_pub[32];
    if (ml_identity_rotate_node_key(ml, new_priv, new_pub) != ESP_OK) {
        coord_fail(ml, noise, state, ML_ERR_STORAGE);
        return;
    }
    ml->rotated_this_session = true;
    ESP_LOGW(TAG, "Node key expired: new key stored, registering with OldNodeKey");

    reg_params_t rp = {
        .stream_id = 3,                 /* stream 1 carried the register that was refused */
        .node_priv = new_priv,
        .node_pub = new_pub,
        .old_node_pub = ml->old_node_pub,
        .followup = NULL,
    };
    ml_register_result_t rr;
    microlink_error_t xerr;
    if (register_exchange(ml, noise, &rp, &rr, &xerr) == 0) {
        ml_register_result_clear(&rr);  /* an AuthURL, if any, is re-issued after the restart */
    }
    memset(new_priv, 0, sizeof(new_priv));
    coord_fail(ml, noise, state, ML_ERR_KEY_ROTATED);
}

/* Arrival time of a queued packet: the net I/O task stamps the low 32 bits of
 * esp_timer at receive, so time spent in the queue is not counted as RTT. */
static int64_t coord_rx_time_us(const ml_rx_packet_t *pkt) {
    int64_t now = esp_timer_get_time();
    if (pkt->rx_us == 0) return now;            /* source without a stamp */
    return now - (int64_t)(uint32_t)((uint32_t)now - pkt->rx_us);
}

/* One STUN reply from stun_rx_queue (the caller frees pkt->data). A netcheck latency
 * probe reply is taken by ml_netcheck_on_stun(); anything else is endpoint discovery,
 * and with send_update a new endpoint goes to the control plane at once. */
static void coord_handle_stun_packet(microlink_t *ml, ml_noise_state_t *noise,
                                     const ml_rx_packet_t *pkt, bool send_update) {
    if (!pkt->data || pkt->len == 0) return;     /* shutdown wake-up (microlink_stop) */
    if (ml_netcheck_on_stun(ml, pkt->data, pkt->len, coord_rx_time_us(pkt))) return;

    uint32_t pub_ip;
    uint16_t pub_port;
    bool parsed = false;

    /* Try IPv4 parse first */
    if (ml_stun_parse_response(pkt->data, pkt->len,
                                &pub_ip, &pub_port)) {
        if (ml->stun_public_ip == 0) {
            /* First STUN result (primary server) */
            ml->stun_public_ip = pub_ip;
            ml->stun_public_port = pub_port;
            ml->stun_retry_count = 0;
            /* Send probe to fallback for symmetric NAT check */
            if (!ml->stun_nat_checked && ml->stun_fallback_ip) {
                ml_stun_send_probe_to(ml, ml->stun_fallback_ip,
                                       ML_STUN_FALLBACK_PORT);
                ESP_LOGI(TAG, "Sent STUN to fallback for NAT type detection");
            }
        } else if (!ml->stun_nat_checked) {
            /* Second STUN result (fallback) — compare ports */
            ml->stun_secondary_port = pub_port;
            ml->stun_nat_checked = true;
            if (ml->stun_public_port != pub_port) {
                ml->nat_mapping_varies = true;
                ESP_LOGW(TAG, "Symmetric NAT detected "
                         "(direct connections unlikely)");
            } else {
                ml->nat_mapping_varies = false;
                ESP_LOGI(TAG, "Cone NAT: port consistent "
                         "(direct connections possible)");
            }
        } else {
            /* Periodic re-probe — update primary result */
            ml->stun_public_ip = pub_ip;
            ml->stun_public_port = pub_port;
            ml->stun_retry_count = 0;
        }
        parsed = true;
    }

    /* Try IPv6 parse (response may contain IPv6 XOR-MAPPED-ADDRESS) */
    if (!parsed) {
        uint8_t ip6[16];
        uint16_t port6;
        if (ml_stun_parse_response_ipv6(pkt->data, pkt->len,
                                         ip6, &port6)) {
            memcpy(ml->stun_public_ip6, ip6, 16);
            ml->stun_public_port6 = port6;
            ml->stun_has_ipv6 = true;
            /* Use IPv6 port for NAT detection if no IPv4 result yet */
            if (ml->stun_public_port == 0) {
                ml->stun_public_port = port6;
            }
            ml->stun_retry_count = 0;  /* Got a result, stop retrying */
            ESP_LOGI(TAG, "STUN IPv6 result obtained");
            /* Trigger NAT type check if not done yet */
            if (!ml->stun_nat_checked && ml->stun_fallback_ip) {
                ml_stun_send_probe_to(ml, ml->stun_fallback_ip,
                                       ML_STUN_FALLBACK_PORT);
                ESP_LOGI(TAG, "Sent STUN to fallback for NAT type detection");
            }
            parsed = true;
        }
    }

    if (parsed) {
        xEventGroupSetBits(ml->events, ML_EVT_STUN_COMPLETE);
        /* Send endpoint update to control plane immediately.
         * With Version >= 68, Stream=true MapRequests have endpoints
         * IGNORED, so we need this separate Stream=false request. */
        if (send_update) do_send_endpoint_update(ml, noise, false);
    }
}

/* STUN replies waiting in stun_rx_queue: at most its depth per pass, so a flood
 * cannot hold the long-poll loop (pings, the control-plane watchdog). */
static void coord_drain_stun(microlink_t *ml, ml_noise_state_t *noise) {
    ml_rx_packet_t pkt;
    for (int i = 0; i < ML_STUN_RX_QUEUE_DEPTH; i++) {
        if (xQueueReceive(ml->stun_rx_queue, &pkt, 0) != pdTRUE) break;
        coord_handle_stun_packet(ml, noise, &pkt, true);
        free(pkt.data);
    }
}

/* The home region changed: the DERP connection follows it, and with the long-poll
 * open the control plane hears the new PreferredDERP at once. */
static void coord_home_changed(microlink_t *ml, ml_noise_state_t *noise, bool long_poll_open) {
    ESP_LOGI(TAG, "Home DERP region: %u", ml->derp_home_region);
    ml->derp_target_gen++;
    /* A connect in flight (to the old region) must not survive; the DERP task keeps a
     * connection that already reached the new home (derp_target_gen). Before
     * registration the DERP task does not connect, so there is nothing to redirect. */
    if (xEventGroupGetBits(ml->events) & ML_EVT_COORD_REGISTERED) {
        xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
    }
    if (long_poll_open) do_send_endpoint_update(ml, noise, true);
}

/* One netcheck round (DERP region latency). Blocks until every planned region replied
 * or ML_NC_STUN_TIMEOUT_MS passed; other STUN replies meanwhile get their usual
 * handling. Returns true when the home region changed. */
static bool coord_run_netcheck(microlink_t *ml, ml_noise_state_t *noise, bool long_poll_open) {
    if (ml_netcheck_begin(ml, esp_timer_get_time())) {
        for (;;) {
            int32_t wait_ms = ml_netcheck_service(ml, esp_timer_get_time());
            if (wait_ms < 0) break;
            TickType_t ticks = pdMS_TO_TICKS(wait_ms);
            if (ticks == 0) ticks = 1;      /* the shortest wait that still blocks */
            ml_rx_packet_t pkt;
            if (xQueueReceive(ml->stun_rx_queue, &pkt, ticks) == pdTRUE) {
                coord_handle_stun_packet(ml, noise, &pkt, long_poll_open);
                free(pkt.data);
            }
            /* microlink_stop() posts an empty item to stun_rx_queue to end the wait. */
            if (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) {
                ml_netcheck_abort(ml);      /* no end-of-round side effects on stop */
                return false;
            }
        }
    }
    if (!ml_netcheck_end(ml, esp_timer_get_time())) return false;
    coord_home_changed(ml, noise, long_poll_open);
    return true;
}

/* Apply one command from the app. FORCE_RECONNECT (microlink_rebind, DERP failure) never
 * leaves a terminal error; only RETRY (microlink_retry) does. */
static void coord_handle_command(microlink_t *ml, coord_state_t *state, ml_coord_cmd_t cmd) {
    switch (cmd) {
    case ML_CMD_CONNECT:
        if (*state == COORD_IDLE) {
            *state = COORD_STUN_PROBE;
            ml->state = ML_STATE_CONNECTING;
        }
        break;
    case ML_CMD_DISCONNECT:
        if (ml->coord_sock >= 0) {
            ml_close_sock(ml->coord_sock);
            ml->coord_sock = -1;
        }
        *state = COORD_IDLE;
        ml->state = ML_STATE_IDLE;
        break;
    case ML_CMD_REBIND:
        /* The public endpoint and NAT type belonged to the old network: never
         * advertise them again. STUN and netcheck run afresh on the new one. */
        ml->stun_public_ip = 0;
        ml->stun_public_port = 0;
        ml->stun_has_ipv6 = false;
        memset(ml->stun_public_ip6, 0, sizeof(ml->stun_public_ip6));
        ml->stun_public_port6 = 0;
        ml->stun_secondary_port = 0;
        ml->stun_nat_checked = false;
        ml->nat_mapping_varies = false;
        ml_netcheck_request_full(ml);
        ml_netcheck_forget_derp_failures(ml);   /* the new network may reach them */
        if (*state != COORD_FAILED) *state = COORD_RECONNECTING;
        break;
    case ML_CMD_FORCE_RECONNECT:
        if (*state != COORD_FAILED) *state = COORD_RECONNECTING;
        break;
    case ML_CMD_RETRY:
        if (*state == COORD_FAILED) {
            ml->last_error = ML_ERR_NONE;
            *state = COORD_RECONNECTING;
        }
        break;
    case ML_CMD_UPDATE_ENDPOINTS:
        /* TODO: Send endpoint update on existing H2 connection */
        break;
    case ML_CMD_RESYNC_NETMAP:
        /* A peer left out of the table is only known again from a full netmap, which
         * FETCH_PEERS reads after a reconnect. Other states read one anyway. */
        if (*state == COORD_LONG_POLL) *state = COORD_RECONNECTING;
        break;
    case ML_CMD_SHUTDOWN_WAKE:
        break;                      /* the loop condition sees ML_EVT_SHUTDOWN_REQUEST */
    }
}

/* The priority name was cleared (ML_EVT_PRIORITY_CLEARED). The tracked peer stays
 * only when CONFIG_ML_PRIORITY_PEER_IP still names it; the main loop acts on the
 * home change (ml_netcheck_take_home_change). */
static void coord_priority_cleared(microlink_t *ml) {
    if (!(xEventGroupClearBits(ml->events, ML_EVT_PRIORITY_CLEARED) & ML_EVT_PRIORITY_CLEARED)) {
        return;
    }
    if (ml->config.priority_peer_ip == 0 ||
        ml->netcheck.peer_ip != ml->config.priority_peer_ip) {
        forget_priority_peer(ml);
    }
    ml_netcheck_apply_home(ml);
}

/* ============================================================================
 * Coordination Task Main Loop
 * ========================================================================== */

void ml_coord_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "Coord task started (Core %d)", xPortGetCoreID());

    coord_state_t state = COORD_IDLE;
    ml_coord_cmd_t cmd;
    uint64_t last_activity_ms = ml_get_time_ms();
    int reconnect_attempts = 0;

    /* Noise protocol state - owned exclusively by this task */
    ml_noise_state_t noise = {0};

    /* Followup wait (COORD_LOGIN_WAIT) */
    reg_stream_t followup_rs = {0};
    bool followup_is_open = false;          /* a Followup request is outstanding */
    uint32_t followup_sid = 0;              /* H2 stream of the next Followup */
    uint64_t followup_not_before_ms = 0;    /* backoff when the server repeats the same URL */
    int followup_repeats = 0;
    uint64_t login_ping_ms = 0;

    /* Wait for WiFi/cellular OR shutdown */
    ESP_LOGI(TAG, "Waiting for WiFi...");
    {
        EventBits_t wb = xEventGroupWaitBits(ml->events,
                             ML_EVT_WIFI_CONNECTED | ML_EVT_SHUTDOWN_REQUEST,
                             pdFALSE, pdFALSE, portMAX_DELAY);
        if (wb & ML_EVT_SHUTDOWN_REQUEST) {
            ESP_LOGI(TAG, "Shutdown requested before WiFi, exiting");
            ml_task_exit(ml, ML_EVT_EXIT_COORD);
            return;
        }
    }

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        /* Check for commands (non-blocking) */
        if (xQueueReceive(ml->coord_cmd_queue, &cmd, 0) == pdTRUE) {
            coord_handle_command(ml, &state, cmd);
        }

        /* A command may have pulled us out of COORD_LOGIN_WAIT. */
        if (state != COORD_LOGIN_WAIT && followup_rs.h2) {
            reg_stream_free(&followup_rs);
            followup_is_open = false;
        }

        /* DERP reconnect is now handled by the DERP I/O task itself.
         * The I/O task checks ML_EVT_DERP_RECONNECT directly. */

        switch (state) {
        case COORD_IDLE:
            vTaskDelay(pdMS_TO_TICKS(100));
            break;

        case COORD_STUN_PROBE:
            ESP_LOGI(TAG, "Running STUN probe...");
            /* Pre-resolve STUN servers (cached, only resolves once) */
            ml_stun_resolve_servers(ml);
            /* Reset retry state for fresh probe sequence */
            ml->stun_retry_count = 1;  /* First probe counts as attempt 1 */
            ml->stun_using_fallback = false;
            ml->stun_last_probe_ms = ml_get_time_ms();
            /* Send first probe to Tailscale STUN primary (IPv4) */
            if (ml->stun_primary_ip) {
                ml_stun_send_probe_to(ml, ml->stun_primary_ip, ML_STUN_PRIMARY_PORT);
            } else if (ml->stun_fallback_ip) {
                ml->stun_using_fallback = true;
                ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
            } else {
                /* Both DNS failed, try hostname-based as last resort */
                ml_stun_send_probe(ml, ML_STUN_PRIMARY_HOST, ML_STUN_PRIMARY_PORT);
            }
            /* Also send IPv6 STUN probe if resolved */
            {
                static const uint8_t zero16[16] = {0};
                if (memcmp(ml->stun_primary_ip6, zero16, 16) != 0) {
                    ml_stun_send_probe_ipv6(ml, ml->stun_primary_ip6, ML_STUN_PRIMARY_PORT);
                }
            }
            state = COORD_DNS_RESOLVE;
            break;

        case COORD_DNS_RESOLVE:
        case COORD_TCP_CONNECT:
            if (do_tcp_connect(ml) < 0) {
                ESP_LOGE(TAG, "TCP connect failed, retrying...");
                state = COORD_RECONNECTING;
                break;
            }
            ml->h2_next_stream_id = 7;  /* Reset H2 stream counter for new connection */
            state = COORD_NOISE_HANDSHAKE;
            break;

        case COORD_NOISE_HANDSHAKE:
            ml->state = ML_STATE_REGISTERING;
            if (do_noise_handshake(ml, &noise) < 0) {
                ESP_LOGE(TAG, "Noise handshake failed");
                ml_close_sock(ml->coord_sock);
                ml->coord_sock = -1;
                state = COORD_RECONNECTING;
                break;
            }
            /* Process proactive server frames (EarlyNoise, H2 SETTINGS)
             * before sending our H2 preface. Extracts nodeKeyChallenge
             * and adjusts rx_nonce. */
            process_proactive_frames(ml, &noise);
            state = COORD_H2_PREFACE;
            break;

        case COORD_H2_PREFACE:
            if (do_h2_preface(ml, &noise) < 0) {
                ESP_LOGE(TAG, "H2 preface failed");
                ml_close_sock(ml->coord_sock);
                ml->coord_sock = -1;
                state = COORD_RECONNECTING;
                break;
            }
            state = COORD_REGISTER;
            break;

        case COORD_REGISTER:
            {
                ESP_LOGI(TAG, "Registering...");
                reg_params_t rp = {
                    .stream_id = 1,
                    .node_priv = ml->wg_private_key,
                    .node_pub = ml->wg_public_key,
                    .old_node_pub = ml->old_node_valid ? ml->old_node_pub : NULL,
                    .followup = NULL,
                };
                ml_register_result_t rr;
                microlink_error_t xerr = ML_ERR_NETWORK;

                if (register_exchange(ml, &noise, &rp, &rr, &xerr) < 0) {
                    /* Transport failure or timeout: typed, never success. Retried. */
                    ESP_LOGE(TAG, "Registration failed");
                    ml->last_error = xerr;
                    ml_close_sock(ml->coord_sock);
                    ml->coord_sock = -1;
                    state = COORD_RECONNECTING;
                    break;
                }

                switch (rr.kind) {
                case ML_REG_OK:
                    ml_set_auth_url(ml, NULL);
                    ml->last_error = ML_ERR_NONE;
                    if (ml->old_node_valid) ml_identity_clear_old_node_key(ml);   /* rotation done */
                    state = COORD_FETCH_PEERS;
                    break;

                case ML_REG_AUTH_URL:
                    /* Interactive login: keep the URL in RAM, publish NEEDS_LOGIN, then
                     * wait for the user on a Followup request (COORD_LOGIN_WAIT). An
                     * auth-key caller cannot show the URL: its key was not accepted. */
                    if (coord_begin_login(ml, &noise, &state, rr.auth_url)) {
                        followup_sid = 3;           /* stream 1 carried this register */
                        followup_repeats = 0;
                        followup_not_before_ms = 0;
                        followup_is_open = false;
                        login_ping_ms = ml_get_time_ms();
                        last_activity_ms = login_ping_ms;
                    }
                    break;

                case ML_REG_NODE_KEY_EXPIRED:
                    coord_handle_key_expired(ml, &noise, &state);
                    break;

                case ML_REG_REJECTED:
                    coord_fail(ml, &noise, &state, ML_ERR_REGISTER_REJECTED);
                    break;

                case ML_REG_TAILNET_LOCK:
                    coord_fail(ml, &noise, &state, ML_ERR_TAILNET_LOCK);
                    break;

                case ML_REG_EMPTY:
                case ML_REG_MALFORMED:
                default:
                    /* Empty or unreadable body: typed, never success. Retried. */
                    ESP_LOGE(TAG, "Registration failed: unusable response");
                    ml->last_error = ML_ERR_PROTOCOL;
                    ml_close_sock(ml->coord_sock);
                    ml->coord_sock = -1;
                    state = COORD_RECONNECTING;
                    break;
                }
                ml_register_result_clear(&rr);
            }
            break;

        case COORD_LOGIN_WAIT:
            {
                /* Non-blocking, in the pattern of COORD_LONG_POLL: at most 50 ms in
                 * select() per pass, PINGs every ML_H2_PING_INTERVAL_MS, commands and
                 * shutdown checked at the loop head. The user may take minutes. */
                uint64_t now = ml_get_time_ms();
                microlink_error_t xerr = ML_ERR_NETWORK;

                if (now - last_activity_ms > ml->t_ctrl_watchdog_ms) {
                    ESP_LOGW(TAG, "Control plane watchdog timeout (login wait)");
                    ml->last_error = ML_ERR_NETWORK;
                    state = COORD_RECONNECTING;
                    break;
                }

                if (now - login_ping_ms >= ML_H2_PING_INTERVAL_MS) {
                    if (send_h2_ping(ml, &noise, now) < 0) {
                        ESP_LOGW(TAG, "H2 PING send failed (login wait), reconnecting");
                        ml->last_error = ML_ERR_NETWORK;
                        state = COORD_RECONNECTING;
                        break;
                    }
                    login_ping_ms = now;
                    last_activity_ms = now;
                }

                if (!followup_is_open) {
                    if (now < followup_not_before_ms) {
                        vTaskDelay(pdMS_TO_TICKS(50));
                        break;
                    }
                    if (followup_open(ml, &noise, &followup_rs, followup_sid) < 0) {
                        ESP_LOGW(TAG, "Followup request failed, reconnecting");
                        ml->last_error = ML_ERR_NETWORK;
                        state = COORD_RECONNECTING;
                        break;
                    }
                    followup_is_open = true;
                    ESP_LOGI(TAG, "Waiting for login (Followup on stream %lu)",
                             (unsigned long)followup_sid);
                }

                int pr = register_poll(ml, &noise, &followup_rs, &xerr);
                if (pr >= 1) last_activity_ms = now;
                if (pr < 0) {
                    ESP_LOGW(TAG, "Followup connection lost");
                    ml->last_error = xerr;
                    state = COORD_RECONNECTING;
                    break;
                }
                if (pr < 2) break;

                /* The server answered the Followup. */
                ml_register_result_t fr;
                ml_register_parse_response(followup_rs.body, followup_rs.body_len, &fr);
                ESP_LOGI(TAG, "Followup response: %d bytes, kind=%d, auth_url=%d error=%d",
                         (int)followup_rs.body_len, (int)fr.kind, fr.auth_url != NULL,
                         fr.error_present);
                reg_stream_free(&followup_rs);
                followup_is_open = false;
                followup_sid += 2;

                switch (fr.kind) {
                case ML_REG_OK:
                    /* Login finished. Stream ids on this connection are spent, so register
                     * again on a fresh one (key refresh, no AuthURL); FETCH_PEERS follows. */
                    ml_set_auth_url(ml, NULL);
                    ml->last_error = ML_ERR_NONE;
                    coord_drop_connection(ml, &noise);
                    ml->state = ML_STATE_CONNECTING;
                    state = COORD_STUN_PROBE;
                    break;

                case ML_REG_AUTH_URL:
                    /* auto.go:381-392: a new URL replaces the old one at once; the same URL
                     * is asked again after the existing exponential backoff. */
                    if (auth_url_equals(ml, fr.auth_url)) {
                        uint32_t backoff_ms = 1000 << (followup_repeats > 4 ? 4 : followup_repeats);
                        if (backoff_ms > ML_CTRL_BACKOFF_MAX_MS) backoff_ms = ML_CTRL_BACKOFF_MAX_MS;
                        followup_repeats++;
                        followup_not_before_ms = now + backoff_ms;
                    } else if (ml_set_auth_url(ml, fr.auth_url) != ESP_OK) {
                        ml->last_error = ML_ERR_PROTOCOL;   /* unusable response; the old URL is gone */
                        state = COORD_RECONNECTING;
                    } else {
                        followup_repeats = 0;
                        followup_not_before_ms = 0;
                    }
                    break;

                case ML_REG_REJECTED:
                    coord_fail(ml, &noise, &state, ML_ERR_REGISTER_REJECTED);
                    break;

                case ML_REG_TAILNET_LOCK:
                    coord_fail(ml, &noise, &state, ML_ERR_TAILNET_LOCK);
                    break;

                case ML_REG_NODE_KEY_EXPIRED:
                    /* Register again on a fresh connection; REGISTER rotates the key. */
                    ml->last_error = ML_ERR_NONE;
                    state = COORD_RECONNECTING;
                    break;

                case ML_REG_EMPTY:
                case ML_REG_MALFORMED:
                default:
                    ml->last_error = ML_ERR_PROTOCOL;
                    state = COORD_RECONNECTING;
                    break;
                }
                ml_register_result_clear(&fr);
            }
            break;

        case COORD_FAILED:
            /* ERROR is published; microlink_retry() queues FORCE_RECONNECT. */
            vTaskDelay(pdMS_TO_TICKS(100));
            break;

        case COORD_FETCH_PEERS:
            ESP_LOGI(TAG, "Fetching peers...");
            ml->machine_auth_known = false;     /* re-learned from this netmap's self node */
            if (do_fetch_peers(ml, &noise) < 0) {
                ESP_LOGW(TAG, "MapRequest failed, will retry");
                if (ml->last_error == ML_ERR_NONE) ml->last_error = ML_ERR_NETWORK;
                ml_close_sock(ml->coord_sock);
                ml->coord_sock = -1;
                state = COORD_RECONNECTING;
                break;
            }

            if (ml->interactive && ml->machine_auth_known && !ml->machine_authorized) {
                /* Logged in, waiting for an administrator (DESIGN section 7.3). Keep the
                 * long-poll open to learn about the approval, but do not signal
                 * ML_EVT_COORD_REGISTERED (wg_mgr waits on it) or connect DERP yet.
                 * Interactive mode only: auth-key callers keep the baseline behaviour. */
                if (do_start_long_poll(ml, &noise) < 0) {
                    ESP_LOGW(TAG, "Failed to start long-poll");
                    ml->last_error = ML_ERR_NETWORK;
                    ml_close_sock(ml->coord_sock);
                    ml->coord_sock = -1;
                    state = COORD_RECONNECTING;
                    break;
                }
                ml->last_error = ML_ERR_NONE;
                reconnect_attempts = 0;
                last_activity_ms = ml_get_time_ms();
                state = COORD_LONG_POLL;
                coord_publish_state(ml, ML_STATE_NEEDS_MACHINE_AUTH);
                break;
            }

            xEventGroupSetBits(ml->events, ML_EVT_COORD_REGISTERED);

            /* Pick the home region before DERP connects to it (the DERP map just
             * arrived, so a full round is due). */
            if (ml_netcheck_due(ml, ml_get_time_ms())) {
                coord_run_netcheck(ml, &noise, false);
            }
            /* The priority peer's region, taken from the peers just parsed. */
            if (ml_netcheck_take_home_change(ml)) coord_home_changed(ml, &noise, false);

            /* The home region is decided: the DERP task may connect now (it never
             * connects on registration alone, only to replace that connection after
             * the round). */
            xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
            if (!ml->derp.connected) {
                /* Wait for DERP to connect (up to 15s) before continuing */
                ESP_LOGI(TAG, "Waiting for DERP I/O task to connect...");
                EventBits_t db = xEventGroupWaitBits(ml->events,
                                    ML_EVT_DERP_CONNECTED | ML_EVT_SHUTDOWN_REQUEST,
                                    pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));
                if (db & ML_EVT_SHUTDOWN_REQUEST) break;    /* the loop ends on it */
            }

            /* Start streaming long-poll for incremental updates */
            if (do_start_long_poll(ml, &noise) < 0) {
                ESP_LOGW(TAG, "Failed to start long-poll (non-fatal)");
            }

            /* Send initial endpoint update if STUN already completed.
             * (STUN runs concurrently and may have results by now.) */
            if (ml->stun_public_ip != 0 || ml->stun_has_ipv6) {
                do_send_endpoint_update(ml, &noise, false);
            }

            /* Send initial HTTP/2 PING immediately to keep connection active
             * before the periodic 5s timer kicks in (server has ~20s idle timeout) */
            {
                uint8_t ping_frame[17];
                ping_frame[0] = 0x00; ping_frame[1] = 0x00; ping_frame[2] = 0x08;
                ping_frame[3] = 0x06; ping_frame[4] = 0x00;
                ping_frame[5] = 0x00; ping_frame[6] = 0x00;
                ping_frame[7] = 0x00; ping_frame[8] = 0x00;
                memset(ping_frame + 9, 0x42, 8);
                noise_send(ml, &noise, ping_frame, sizeof(ping_frame));
                ESP_LOGI(TAG, "Sent initial HTTP/2 PING after long-poll");
            }

            state = COORD_LONG_POLL;
            ml->state = ML_STATE_CONNECTED;
            ml->last_error = ML_ERR_NONE;
            reconnect_attempts = 0;
            last_activity_ms = ml_get_time_ms();

            /* Notify app */
            if (ml->state_cb) {
                ml->state_cb(ml, ML_STATE_CONNECTED, ml->state_cb_data);
            }
            break;

        case COORD_LONG_POLL:
            {
                uint64_t now = ml_get_time_ms();

                /* Check control plane watchdog (120s) */
                if (now - last_activity_ms > ml->t_ctrl_watchdog_ms) {
                    ESP_LOGW(TAG, "Control plane watchdog timeout");
                    state = COORD_RECONNECTING;
                    break;
                }

                /* STUN replies: latency probes first, then endpoint discovery. */
                coord_drain_stun(ml, &noise);

                /* DERP region latency (netcheck): after a DERP map, a rebind, and
                 * every STUN re-probe interval. Blocks at most ML_NC_STUN_TIMEOUT_MS. */
                if (ml_netcheck_due(ml, now)) {
                    coord_run_netcheck(ml, &noise, true);
                }

                /* STUN retry logic: 3 attempts per server, 2s apart, then fallback */
                if (ml->stun_retry_count > 0 && ml->stun_retry_count <= ML_STUN_MAX_RETRIES) {
                    if (now - ml->stun_last_probe_ms > ML_STUN_RETRY_INTERVAL_MS) {
                        if (!ml->stun_using_fallback && ml->stun_primary_ip) {
                            ml_stun_send_probe_to(ml, ml->stun_primary_ip, ML_STUN_PRIMARY_PORT);
                        } else if (ml->stun_fallback_ip) {
                            ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
                        }
                        ml->stun_last_probe_ms = now;
                        ml->stun_retry_count++;
                        if (ml->stun_retry_count > ML_STUN_MAX_RETRIES && !ml->stun_using_fallback) {
                            /* Primary exhausted, switch to fallback */
                            ESP_LOGW(TAG, "STUN primary failed after %d retries, trying fallback",
                                     ML_STUN_MAX_RETRIES);
                            ml->stun_using_fallback = true;
                            ml->stun_retry_count = 1;
                            if (ml->stun_fallback_ip) {
                                ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
                                ml->stun_last_probe_ms = now;
                            }
                        }
                    }
                }

                /* Periodic STUN re-probe (every 23s) — fresh probe sequence */
                static uint64_t last_stun_ms = 0;
                if (now - last_stun_ms > ml->t_stun_interval_ms) {
                    ml->stun_retry_count = 1;
                    ml->stun_using_fallback = false;
                    ml->stun_last_probe_ms = now;
                    /* IPv4 probe */
                    if (ml->stun_primary_ip) {
                        ml_stun_send_probe_to(ml, ml->stun_primary_ip, ML_STUN_PRIMARY_PORT);
                    } else if (ml->stun_fallback_ip) {
                        ml->stun_using_fallback = true;
                        ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
                    } else {
                        ml_stun_send_probe(ml, ML_STUN_PRIMARY_HOST, ML_STUN_PRIMARY_PORT);
                    }
                    /* IPv6 probe (alongside IPv4) */
                    {
                        static const uint8_t zero16[16] = {0};
                        if (memcmp(ml->stun_primary_ip6, zero16, 16) != 0) {
                            ml_stun_send_probe_ipv6(ml, ml->stun_primary_ip6, ML_STUN_PRIMARY_PORT);
                        }
                    }
                    last_stun_ms = now;
                }

                /* Periodic DERP NotePreferred keepalive (every 60s) */
                static uint64_t last_derp_keepalive_ms = 0;
                if (ml->derp.connected && now - last_derp_keepalive_ms > 60000) {
                    uint8_t preferred = 0x01;
                    uint8_t *ka_data = malloc(1);
                    if (ka_data) {
                        *ka_data = preferred;
                        ml_derp_tx_item_t ka_item = {
                            .data = ka_data,
                            .len = 1,
                            .frame_type = 0x07,  /* NotePreferred */
                        };
                        memset(ka_item.dest_pubkey, 0, 32);
                        if (xQueueSend(ml->derp_tx_queue, &ka_item, 0) != pdTRUE) {
                            free(ka_data);
                        }
                    }
                    last_derp_keepalive_ms = now;
                }

                /* Key expiry check (every 60s) — re-register if expired */
                if (ml->key_expiry_epoch > 0 || ml->key_expired) {
                    static uint64_t last_expiry_check_ms = 0;
                    if (now - last_expiry_check_ms > 60000) {
                        last_expiry_check_ms = now;
                        if (ml->key_expired) {
                            /* Register again: the server answers NodeKeyExpired and REGISTER
                             * rotates the node key (DESIGN section 12). Re-sending the same
                             * key, as the baseline did, is answered NodeKeyExpired forever. */
                            ESP_LOGW(TAG, "Node key expired, re-registering");
                            state = COORD_RECONNECTING;
                            break;
                        }
                        /* Warn 1 hour before expiry (rough uptime-based check) */
                        /* Note: key_expiry_epoch is absolute Unix time, we compare with
                         * approximate boot-relative time. For accurate check we'd need
                         * SNTP, but this catches the Expired flag from the server. */
                    }
                }

                /* Send HTTP/2 PING every 5 seconds to keep control plane alive.
                 * The server has a ~20s idle timeout; PINGs maintain bidirectional
                 * activity and are what actually keep us "online". (v1 reference) */
                static uint64_t last_h2_ping_ms = 0;
                if (now - last_h2_ping_ms >= ML_H2_PING_INTERVAL_MS) {
                    uint8_t ping_frame[17];
                    ping_frame[0] = 0x00; ping_frame[1] = 0x00; ping_frame[2] = 0x08;
                    ping_frame[3] = 0x06;  /* Type: PING */
                    ping_frame[4] = 0x00;  /* Flags: none */
                    ping_frame[5] = 0x00; ping_frame[6] = 0x00;
                    ping_frame[7] = 0x00; ping_frame[8] = 0x00;  /* Stream 0 */
                    /* Opaque 8-byte payload (timestamp for identification) */
                    uint64_t ping_id = now;
                    for (int b = 0; b < 8; b++)
                        ping_frame[9 + b] = (ping_id >> (56 - b * 8)) & 0xFF;
                    int ping_ret = noise_send(ml, &noise, ping_frame, sizeof(ping_frame));
                    if (ping_ret >= 0) {
                        last_h2_ping_ms = now;
                        last_activity_ms = now;
                    } else {
                        ESP_LOGW(TAG, "H2 PING send failed, reconnecting");
                        state = COORD_RECONNECTING;
                        break;
                    }
                }

                /* Poll for streaming MapResponse updates */
                bool map_unparsed = false;
                int poll_ret = poll_map_update(ml, &noise, &map_unparsed);
                if (poll_ret > 0) {
                    last_activity_ms = now;  /* Reset watchdog */
                } else if (poll_ret < 0) {
                    ESP_LOGW(TAG, "Long-poll connection lost");
                    state = COORD_RECONNECTING;
                    break;
                }

                if (ml->state == ML_STATE_NEEDS_MACHINE_AUTH &&
                    (ml->machine_authorized || map_unparsed)) {
                    /* The approval arrived, or a netmap update did that poll_map_update()
                     * could not read (it takes one Noise frame; a big update spans several).
                     * Either way the delta cannot be trusted to carry the whole netmap:
                     * register again on a fresh connection and let FETCH_PEERS read the
                     * full one, as after a Followup success. */
                    ESP_LOGI(TAG, "%s: reading the full netmap on a new connection",
                             ml->machine_authorized ? "Machine approved" : "Netmap update not parsed");
                    coord_drop_connection(ml, &noise);
                    ml->state = ML_STATE_CONNECTING;
                    state = COORD_STUN_PROBE;
                    break;
                }

                /* The priority peer moved or was cleared, or the DERP map changed. */
                coord_priority_cleared(ml);
                if (ml_netcheck_take_home_change(ml)) coord_home_changed(ml, &noise, true);

                vTaskDelay(pdMS_TO_TICKS(50));
            }
            break;

        case COORD_RECONNECTING:
            {
                uint32_t backoff_ms = 1000 << (reconnect_attempts > 4 ? 4 : reconnect_attempts);
                if (backoff_ms > ML_CTRL_BACKOFF_MAX_MS) backoff_ms = ML_CTRL_BACKOFF_MAX_MS;

                ESP_LOGI(TAG, "Reconnecting in %lu ms (attempt %d)",
                         (unsigned long)backoff_ms, reconnect_attempts + 1);

                ml->state = ML_STATE_RECONNECTING;

                /* Wait on command queue with backoff timeout (interruptible!) */
                ml_coord_cmd_t wake_cmd;
                if (xQueueReceive(ml->coord_cmd_queue, &wake_cmd, pdMS_TO_TICKS(backoff_ms)) == pdTRUE) {
                    /* Every command counts here too (REBIND must clear the old STUN
                     * endpoint); DISCONNECT leaves for IDLE. */
                    coord_handle_command(ml, &state, wake_cmd);
                    if (state != COORD_RECONNECTING) break;
                    if (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) break;
                }

                reconnect_attempts++;

                /* Close old connection */
                if (ml->coord_sock >= 0) {
                    ml_close_sock(ml->coord_sock);
                    ml->coord_sock = -1;
                }

                /* Reset Noise state for fresh handshake */
                memset(&noise, 0, sizeof(noise));

                state = COORD_STUN_PROBE;
            }
            break;
        }
    }

    /* Cleanup */
    reg_stream_free(&followup_rs);
    if (ml->coord_sock >= 0) {
        ml_close_sock(ml->coord_sock);
        ml->coord_sock = -1;
    }
    memset(&noise, 0, sizeof(noise));

    ml_netcheck_release(ml);        /* round buffers; DNS work is detached */
    ESP_LOGI(TAG, "Coord task exiting");
    ml_task_exit(ml, ML_EVT_EXIT_COORD);
}
