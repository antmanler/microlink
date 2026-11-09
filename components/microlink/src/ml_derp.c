/**
 * @file ml_derp.c
 * @brief Unified DERP I/O Task + Connection Management
 *
 * Single task handles BOTH reading and writing to DERP TLS connection.
 * This eliminates the need for a TLS mutex since only one task touches
 * the SSL context. Matches v1's single-threaded DERP model.
 *
 * Architecture:
 * - Drain the TX queue first (TLS write), then read up to a burst of frames
 * - Then sleep in select() on the socket and derp_wake_fd until the socket is
 *   readable, a producer queued TX, a reconnect or shutdown was requested, or the
 *   next log deadline; never while TLS still holds read plaintext
 * - No mutex needed — single task owns the SSL context exclusively
 *
 * Backpressure strategy (from tailscaled):
 * When queue is full, dequeue oldest packet and retry up to 3 times.
 * If still full, drop the new packet.
 *
 * Reference: tailscale/wgengine/magicsock/derp.go (runDerpWriter)
 *            tailscale/derp/derphttp/derphttp_client.go
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "nacl_box.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#ifndef CONFIG_ML_ENABLE_CELLULAR
#include <sys/select.h>
#include <unistd.h>
#include "esp_vfs_eventfd.h"
#endif

static const char *TAG = "ml_derp";

/* Timeout for DERP connection handshake operations */
#define DERP_CONNECT_TIMEOUT_MS  10000

/* DERP I/O task log deadlines: the heartbeat and status lines. When connected,
 * the task sleeps until the earlier one. */
#define DERP_HEARTBEAT_LOG_MS    5000
#define DERP_STATUS_LOG_MS       10000

/* ============================================================================
 * Custom BIO callbacks for TLS I/O (ml_read_sock/ml_write_sock: lwIP or AT)
 * ========================================================================== */

/**
 * Custom recv for mbedtls BIO. Until the HTTP upgrade the socket blocks and
 * SO_RCVTIMEO bounds each read; after it the socket is O_NONBLOCK and a read
 * with no data returns at once.
 * Returns bytes read, or MBEDTLS_ERR_SSL_TIMEOUT, MBEDTLS_ERR_SSL_WANT_READ.
 */
static int ml_derp_bio_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                                      uint32_t timeout) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    /* Set SO_RCVTIMEO to the requested timeout.
     * If timeout is 0 (mbedTLS default = "no timeout"), use 10s as a sane
     * default to avoid indefinite blocking on AT sockets. */
    uint32_t effective_timeout = (timeout > 0) ? timeout : DERP_CONNECT_TIMEOUT_MS;
    struct timeval tv;
    tv.tv_sec = effective_timeout / 1000;
    tv.tv_usec = (effective_timeout % 1000) * 1000;
    ml_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int ret = (int)ml_read_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;
}

/**
 * Custom send for mbedtls BIO.
 */
static int ml_derp_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)ml_write_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

/* DERP frame types */
#define DERP_FRAME_SERVER_KEY   0x01
#define DERP_FRAME_CLIENT_INFO  0x02
#define DERP_FRAME_SERVER_INFO  0x03
#define DERP_FRAME_SEND_PACKET  0x04
#define DERP_FRAME_RECV_PACKET  0x05
#define DERP_FRAME_KEEP_ALIVE   0x06
#define DERP_FRAME_NOTE_PREFERRED 0x07
#define DERP_FRAME_PEER_GONE    0x08
#define DERP_FRAME_PING         0x12
#define DERP_FRAME_PONG         0x13

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* ============================================================================
 * TLS Read/Write Helpers
 * ========================================================================== */

/**
 * Read exactly `len` bytes via TLS with timeout and WANT_READ retry.
 * Returns number of bytes read on success, -1 on error, -2 on timeout.
 */
static int derp_tls_read_all(microlink_t *ml, uint8_t *data, size_t len, int timeout_ms) {
    size_t received = 0;
    uint64_t start_ms = ml_get_time_ms();

    while (received < len) {
        if (timeout_ms > 0 && (ml_get_time_ms() - start_ms) > (uint64_t)timeout_ms) {
            ESP_LOGW(TAG, "derp_tls_read_all timeout (%d/%d bytes in %dms)",
                     (int)received, (int)len, timeout_ms);
            return -2;
        }

        int ret = mbedtls_ssl_read(&ml->derp.ssl, data + received, len - received);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ESP_LOGW(TAG, "DERP server closed connection");
                return -1;
            }
            ESP_LOGE(TAG, "TLS read failed: -0x%04x", -ret);
            return -1;
        }
        if (ret == 0) {
            ESP_LOGW(TAG, "TLS connection closed by peer (%d/%d bytes)",
                     (int)received, (int)len);
            return -1;
        }
        received += ret;
    }
    return (int)received;
}

/**
 * Read a DERP frame header (5 bytes: type + 4-byte BE length) with timeout.
 */
static esp_err_t derp_recv_frame_header(microlink_t *ml, uint8_t *type,
                                          uint32_t *len, int timeout_ms) {
    uint8_t header[5];
    int ret = derp_tls_read_all(ml, header, 5, timeout_ms);
    if (ret < 0) {
        return (ret == -2) ? ESP_ERR_TIMEOUT : ESP_FAIL;
    }

    *type = header[0];
    *len = ((uint32_t)header[1] << 24) |
           ((uint32_t)header[2] << 16) |
           ((uint32_t)header[3] << 8) |
           (uint32_t)header[4];

    return ESP_OK;
}

/**
 * Write exactly `len` bytes via TLS with WANT_WRITE retry.
 * Returns bytes written on success, -1 on error.
 * No mutex needed — called only from the DERP I/O task.
 */
static int derp_tls_write_all(microlink_t *ml, const uint8_t *data, size_t len) {
    size_t written = 0;
    int retries = 0;
    const int max_retries = 50;  /* 50 * 10ms = 500ms max */

    while (written < len) {
        int ret = mbedtls_ssl_write(&ml->derp.ssl, data + written, len - written);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                vTaskDelay(pdMS_TO_TICKS(10));
                if (++retries > max_retries) {
                    ESP_LOGW(TAG, "TLS write timeout after %d retries", retries);
                    return -1;
                }
                continue;
            }
            ESP_LOGE(TAG, "TLS write failed: -0x%04x", -ret);
            return -1;
        }
        written += ret;
        retries = 0;
    }
    return (int)written;
}

/* Write a complete DERP frame via TLS */
static int derp_write_frame(microlink_t *ml, uint8_t type,
                             const uint8_t *payload, uint32_t len) {
    /* 5-byte header: 1 type + 4 length (big-endian) */
    uint8_t header[5];
    header[0] = type;
    header[1] = (len >> 24) & 0xFF;
    header[2] = (len >> 16) & 0xFF;
    header[3] = (len >> 8) & 0xFF;
    header[4] = len & 0xFF;

    if (derp_tls_write_all(ml, header, 5) < 0) return -1;

    if (len > 0 && payload) {
        if (derp_tls_write_all(ml, payload, len) < 0) return -1;
    }
    return 0;
}

/* Send a packet to a peer via DERP */
static int derp_send_packet(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    /* SendPacket frame: 32-byte dest key + payload */
    size_t frame_len = 32 + len;
    uint8_t *frame = malloc(frame_len);
    if (!frame) return -1;

    memcpy(frame, dest_key, 32);
    memcpy(frame + 32, data, len);

    int ret = derp_write_frame(ml, DERP_FRAME_SEND_PACKET, frame, frame_len);
    if (ret < 0) {
        ESP_LOGW(TAG, "derp_send_packet FAILED: len=%d", (int)len);
    }
    free(frame);
    return ret;
}

/* ============================================================================
 * DERP Frame Reading and Dispatch (runs on DERP I/O task)
 * ========================================================================== */

/* Packet classification */
typedef enum {
    PKT_DISCO,
    PKT_STUN,
    PKT_WIREGUARD,
    PKT_UNKNOWN,
} pkt_type_t;

static pkt_type_t classify_packet(const uint8_t *data, size_t len) {
    if (len >= 20 && (data[0] == 0x00 || data[0] == 0x01) && data[1] == 0x01) {
        return PKT_STUN;
    }
    if (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0) {
        return PKT_DISCO;
    }
    if (len >= 4) {
        return PKT_WIREGUARD;
    }
    return PKT_UNKNOWN;
}

static void route_derp_packet(microlink_t *ml, uint8_t *data, size_t len,
                               const uint8_t *src_pubkey) {
    pkt_type_t type = classify_packet(data, len);

    ml_rx_packet_t pkt = {
        .data = data,
        .len = len,
        .via_derp = true,
    };
    memcpy(pkt.src_pubkey, src_pubkey, 32);

    QueueHandle_t target = (type == PKT_DISCO) ? ml->disco_rx_queue : ml->wg_rx_queue;
    if (xQueueSend(target, &pkt, 0) != pdTRUE) {
        free(data);
    } else {
        ml_wg_mgr_wake(ml);
    }
}

/* Dispatch a received DERP frame */
static void dispatch_derp_frame(microlink_t *ml, uint8_t frame_type,
                                 uint8_t *src_key, uint8_t *payload, size_t payload_len) {
    switch (frame_type) {
    case DERP_FRAME_RECV_PACKET:
        if (payload) {
            ESP_LOGI(TAG, "DERP RecvPacket: %d bytes, hdr=%02x",
                     (int)payload_len,
                     payload_len > 0 ? payload[0] : 0xFF);
            route_derp_packet(ml, payload, payload_len, src_key);
            return;  /* payload ownership transferred */
        }
        break;

    case DERP_FRAME_KEEP_ALIVE:
        ESP_LOGD(TAG, "DERP KeepAlive received");
        break;

    case DERP_FRAME_PING:
        /* Echo ping data back as PONG directly (single-threaded, safe to write) */
        if (payload && payload_len > 0) {
            ESP_LOGD(TAG, "DERP PING received, sending PONG");
            derp_write_frame(ml, DERP_FRAME_PONG, payload, payload_len);
        }
        break;

    case DERP_FRAME_PONG:
        ESP_LOGD(TAG, "DERP PONG received");
        break;

    case DERP_FRAME_PEER_GONE:
        if (payload && payload_len >= 32) {
            ESP_LOGI(TAG, "DERP PeerGone (len=%d)", (int)payload_len);
        }
        break;

    default:
        ESP_LOGD(TAG, "DERP frame type 0x%02x ignored (%d bytes)",
                 frame_type, (int)payload_len);
        break;
    }

    if (payload) free(payload);
}

/**
 * Try to read one DERP frame.
 * The socket is O_NONBLOCK, so ssl_read returns at once when no record is there
 * (SO_RCVTIMEO does not apply to a nonblocking read). The task waits in select().
 * Returns: 1 = frame read and dispatched, 0 = no data, <0 = error
 */
static int poll_derp_read(microlink_t *ml) {
    if (!ml->derp.connected || ml->derp.sockfd < 0) return -1;

    /* Read the 5-byte frame header; returns at once if nothing is buffered. */
    uint8_t header[5];
    int n = mbedtls_ssl_read(&ml->derp.ssl, header, 5);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE ||
        n == MBEDTLS_ERR_SSL_TIMEOUT) {
        return 0;  /* No data available */
    }
    if (n <= 0) {
        ESP_LOGW(TAG, "DERP header read returned %d (0x%04x)", n, n < 0 ? -n : 0);
        return n;
    }
    if (n < 5) {
        ESP_LOGW(TAG, "DERP partial header: got %d of 5 bytes", n);
        return -1;
    }

    uint8_t frame_type = header[0];
    uint32_t len = (header[1] << 24) | (header[2] << 16) | (header[3] << 8) | header[4];

    uint8_t src_key[32] = {0};
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (len == 0) {
        dispatch_derp_frame(ml, frame_type, src_key, NULL, 0);
        return 1;
    }

    if (len > 65536) {
        ESP_LOGW(TAG, "DERP frame too large: %lu", (unsigned long)len);
        return -1;
    }

    /* Read frame payload - we already got the header so payload should follow.
     * Use longer timeout (2s) since we KNOW data is coming. */
    uint8_t *buf = ml_psram_malloc(len);
    if (!buf) return -1;

    size_t total_read = 0;
    uint64_t payload_start = ml_get_time_ms();
    while (total_read < len) {
        /* Safety timeout: 5 seconds for payload */
        if (ml_get_time_ms() - payload_start > 5000) {
            ESP_LOGW(TAG, "DERP payload timeout at %d/%lu bytes",
                     (int)total_read, (unsigned long)len);
            free(buf);
            return -1;
        }
        n = mbedtls_ssl_read(&ml->derp.ssl, buf + total_read, len - total_read);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE ||
            n == MBEDTLS_ERR_SSL_TIMEOUT) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        if (n <= 0) {
            ESP_LOGW(TAG, "DERP payload read error: %d (0x%04x) at %d/%lu bytes",
                     n, n < 0 ? -n : 0, (int)total_read, (unsigned long)len);
            free(buf);
            return n;
        }
        total_read += n;
    }

    /* For RecvPacket (0x05): first 32 bytes are sender's public key */
    if (frame_type == DERP_FRAME_RECV_PACKET && len > 32) {
        memcpy(src_key, buf, 32);
        payload = malloc(len - 32);
        if (payload) {
            memcpy(payload, buf + 32, len - 32);
            payload_len = len - 32;
        }
        free(buf);
    } else {
        payload = buf;
        payload_len = len;
    }

    dispatch_derp_frame(ml, frame_type, src_key, payload, payload_len);
    return 1;
}

/* ============================================================================
 * DERP TX Queue Processing
 * ========================================================================== */

/* Queue a packet for DERP TX with backpressure */
esp_err_t ml_derp_queue_send(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    if (!ml || !dest_key || !data || len == 0) return ESP_ERR_INVALID_ARG;

    uint8_t *pkt_data = malloc(len);
    if (!pkt_data) return ESP_ERR_NO_MEM;
    memcpy(pkt_data, data, len);

    ml_derp_tx_item_t item = {
        .data = pkt_data,
        .len = len,
        .frame_type = DERP_FRAME_SEND_PACKET,
    };
    memcpy(item.dest_pubkey, dest_key, 32);

    /* WG handshake packets (type 1=init, 2=response) get priority — front of queue.
     * This ensures handshake responses aren't delayed behind DISCO pings. */
    bool is_wg_handshake = (len >= 4 && (data[0] == 0x01 || data[0] == 0x02));

    /* Try to send to queue */
    if ((is_wg_handshake ? xQueueSendToFront(ml->derp_tx_queue, &item, 0)
                         : xQueueSend(ml->derp_tx_queue, &item, 0)) == pdTRUE) {
        ml_derp_wake(ml);
        return ESP_OK;
    }

    /* Queue full - backpressure: drop oldest, retry up to 3 times */
    for (int i = 0; i < 3; i++) {
        ml_derp_tx_item_t dropped;
        if (xQueueReceive(ml->derp_tx_queue, &dropped, 0) == pdTRUE) {
            free(dropped.data);  /* Drop oldest */
        }
        if (xQueueSend(ml->derp_tx_queue, &item, 0) == pdTRUE) {
            ml_derp_wake(ml);
            return ESP_OK;
        }
    }

    /* Still full after 3 attempts, drop new packet */
    free(pkt_data);
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * DERP I/O task wake-up
 * ========================================================================== */

#ifndef CONFIG_ML_ENABLE_CELLULAR
/* MicroLink keeps per-process state in file statics (ml_wg_mgr.c probe table,
 * ml_coord.c keepalive timers), so there is one instance, with one eventfd. */
#define ML_EVENTFD_MAX_FDS  1

esp_err_t ml_derp_wake_init(microlink_t *ml) {
    const esp_vfs_eventfd_config_t cfg = { .max_fds = ML_EVENTFD_MAX_FDS };
    esp_err_t err = esp_vfs_eventfd_register(&cfg);
    /* MicroLink registers the eventfd VFS with one slot if nobody did, so an app
     * that needs more eventfds must register first with its own count.
     * ESP_ERR_INVALID_STATE: the application registered it already. */
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "eventfd VFS register failed: %s", esp_err_to_name(err));
        return err;
    }
    ml->derp_wake_fd = eventfd(0, 0);
    if (ml->derp_wake_fd < 0) {
        ESP_LOGE(TAG, "eventfd failed: errno %d", errno);
        return ESP_FAIL;
    }
    return ESP_OK;
}

void ml_derp_wake_deinit(microlink_t *ml) {
    if (ml->derp_wake_fd >= 0) {
        close(ml->derp_wake_fd);
        ml->derp_wake_fd = -1;
    }
}

void ml_derp_wake(microlink_t *ml) {
    uint64_t one = 1;
    if (ml->derp_wake_fd >= 0) write(ml->derp_wake_fd, &one, sizeof(one));
}

/* Connected and idle: no TX queued, no plaintext left in TLS. Sleeps until the
 * socket is readable, derp_wake_fd is written, or timeout_ms passes. */
static void derp_wait_connected(microlink_t *ml, uint32_t timeout_ms) {
    int sock = ml->derp.sockfd;
    int efd = ml->derp_wake_fd;
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(sock, &rd);
    FD_SET(efd, &rd);
    struct timeval tv = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    int n = select((sock > efd ? sock : efd) + 1, &rd, NULL, NULL, &tv);
    if (n < 0) {
        ESP_LOGW(TAG, "DERP select failed: errno %d", errno);
        return;
    }
    if (n > 0 && FD_ISSET(efd, &rd)) {
        /* Reset the counter. A producer that wrote after this read also queued
         * its item first, so the next TX drain finds it. */
        uint64_t count;
        read(efd, &count, sizeof(count));
    }
}
#else
/* Cellular builds: the AT socket bridge has no select() over an eventfd, so the
 * connected DERP task polls (ml_derp_tx_task) and nothing needs waking. */
esp_err_t ml_derp_wake_init(microlink_t *ml) {
    ml->derp_wake_fd = -1;
    return ESP_OK;
}
void ml_derp_wake_deinit(microlink_t *ml) { (void)ml; }
void ml_derp_wake(microlink_t *ml) { (void)ml; }
#endif

/* Not connected: nothing to read or send. Sleeps until coord asks for a connection,
 * a reconnect or shutdown is requested, or the connect backoff ends; with no
 * attempt due, without a timeout. Registration alone needs no wake: an attempt
 * needs home_decided, which only CONNECT_REQ sets, and coord sets CONNECT_REQ
 * after every registration. */
static void derp_wait_disconnected(microlink_t *ml, const ml_derp_retry_t *retry) {
    bool registered = (xEventGroupGetBits(ml->events) & ML_EVT_COORD_REGISTERED) != 0;
    EventBits_t wait = ML_EVT_SHUTDOWN_REQUEST | ML_EVT_DERP_CONNECT_REQ | ML_EVT_DERP_RECONNECT;
    TickType_t ticks = portMAX_DELAY;
    if (registered && retry->home_decided) {
        uint64_t now = ml_get_time_ms();
        ticks = ml_ms_to_ticks_ceil(retry->next_ms > now ? retry->next_ms - now : 0);
    }
    xEventGroupWaitBits(ml->events, wait, pdFALSE, pdFALSE, ticks);
}

/* ============================================================================
 * Unified DERP I/O Task
 * ========================================================================== */

/* A connect failed, or the connection broke before its first frame: back off and
 * retry the home region, whatever it is, for as long as it takes. A region whose
 * wait reached the maximum is reported to netcheck, which leaves it out of the
 * latency choice (never the priority peer's region) until it carries a frame. */
static void derp_attempt_failed(microlink_t *ml, ml_derp_retry_t *retry) {
    uint32_t wait_ms = ml_derp_retry_failed(retry, ml_get_time_ms(), esp_random());
    if (ml_derp_backoff_capped(retry->failures)) {
        if (ml->derp_ok_region == retry->region) ml->derp_ok_region = 0;
        ml->derp_failed_region = retry->region;
    }
    ESP_LOGW(TAG, "DERP region %u failed (%d in a row), next attempt in %lu ms",
             retry->region, retry->failures, (unsigned long)wait_ms);
}

/* A frame was read on the connection (ServerInfo during the handshake counts). */
static void derp_frame_read(microlink_t *ml, ml_derp_retry_t *retry) {
    if (!ml_derp_retry_frame(retry)) return;
    /* The region carries traffic: netcheck may choose it again. */
    if (ml->derp_failed_region == retry->region) ml->derp_failed_region = 0;
    ml->derp_ok_region = retry->region;
}

void ml_derp_tx_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "DERP I/O task started (Core %d)", xPortGetCoreID());

    uint32_t frames_rx = 0;
    uint32_t frames_tx = 0;
    uint64_t last_status_ms = 0;
    uint32_t loop_count = 0;
    uint64_t last_heartbeat_ms = 0;
    /* Connect retry (magicsock runDerpReader + util/backoff), ml_netcheck.c. */
    ml_derp_retry_t retry = {0};

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        loop_count++;
        uint64_t loop_start = ml_get_time_ms();

        /* Heartbeat - proves task is alive (while connected; a disconnected task
         * sleeps until its next connect attempt or request) */
        if (loop_start - last_heartbeat_ms >= DERP_HEARTBEAT_LOG_MS) {
            ESP_LOGW(TAG, "HEARTBEAT: loop=%lu conn=%d rx=%lu tx=%lu stack_free=%lu",
                     (unsigned long)loop_count, ml->derp.connected,
                     (unsigned long)frames_rx, (unsigned long)frames_tx,
                     (unsigned long)uxTaskGetStackHighWaterMark(NULL));
            last_heartbeat_ms = loop_start;
        }

        /* ---- Periodic status logging (connected, or when a disconnected wait ends) ---- */
        {
            uint64_t now_ms = loop_start;
            if (now_ms - last_status_ms >= DERP_STATUS_LOG_MS) {
                ESP_LOGI(TAG, "DERP status: connected=%d fd=%d rx=%lu tx=%lu loops=%lu",
                         ml->derp.connected, ml->derp.sockfd,
                         (unsigned long)frames_rx, (unsigned long)frames_tx,
                         (unsigned long)loop_count);
                last_status_ms = now_ms;
            }
        }

        /* ---- Connection upkeep: requests from coord, then connect with backoff ---- */
        {
            EventBits_t bits = xEventGroupGetBits(ml->events);
            if (bits & ML_EVT_DERP_CONNECT_REQ) {
                /* Coord registered and decided the home region: try now. */
                xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
            }
            ml_derp_retry_on_bits(&retry, (bits & ML_EVT_COORD_REGISTERED) != 0,
                                  (bits & ML_EVT_DERP_CONNECT_REQ) != 0);
            if ((bits & ML_EVT_DERP_RECONNECT) && ml->derp.connected &&
                ml->derp.target_gen == ml->derp_target_gen &&
                ml->derp.region == ml->derp_home_region) {
                /* The request predates this connection: it completed after the last
                 * rebind or region change, to the home region. Keep it. */
                xEventGroupClearBits(ml->events, ML_EVT_DERP_RECONNECT);
                ESP_LOGI(TAG, "DERP reconnect request predates the current connection, kept");
            } else if (bits & ML_EVT_DERP_RECONNECT) {
                xEventGroupClearBits(ml->events, ML_EVT_DERP_RECONNECT);
                ESP_LOGW(TAG, "DERP reconnect requested (was %s)",
                         ml->derp.connected ? "connected" : "disconnected");
                ml_derp_disconnect(ml);
                retry.awaiting_frame = false;
                retry.next_ms = 0;          /* reconnected below */
            }

            /* Connect while registered, for as long as it takes. */
            if (ml_derp_retry_due(&retry, ml->derp.connected,
                                  (bits & ML_EVT_COORD_REGISTERED) != 0, ml_get_time_ms())) {
                uint16_t region = ml->derp_home_region;
                ml_derp_retry_attempt(&retry, region);
                if (ml_derp_connect(ml, region) == ESP_OK) {
                    if (ml->derp.server_info) derp_frame_read(ml, &retry);
                } else {
                    derp_attempt_failed(ml, &retry);
                }
            }
        }

        if (!ml->derp.connected) {
            derp_wait_disconnected(ml, &retry);
            continue;
        }

        /* ---- Phase 1: Drain TX queue FIRST (prioritize outgoing) ---- */
        {
            for (int tx_count = 0; tx_count < 8; tx_count++) {
                ml_derp_tx_item_t item;
                if (xQueueReceive(ml->derp_tx_queue, &item, 0) != pdTRUE) {
                    break;
                }
                if (!ml->derp.connected) {
                    free(item.data);
                    continue;
                }
                int ret;
                if (item.frame_type == DERP_FRAME_SEND_PACKET) {
                    ESP_LOGI(TAG, "DERP TX: SendPacket %d bytes, hdr=%02x",
                             (int)item.len, item.data[0]);
                    ret = derp_send_packet(ml, item.dest_pubkey, item.data, item.len);
                } else {
                    ret = derp_write_frame(ml, item.frame_type, item.data, item.len);
                }
                if (ret < 0) {
                    ESP_LOGW(TAG, "DERP write failed");
                    ml_derp_disconnect(ml);
                    derp_attempt_failed(ml, &retry);
                } else {
                    frames_tx++;
                }
                free(item.data);
            }
        }

        if (!ml->derp.connected) continue;

        /* ---- Phase 2: Poll for incoming DERP frames ---- */
        {
            int burst;
            for (burst = 0; burst < 4; burst++) {
                int ret = poll_derp_read(ml);
                if (ret > 0) {
                    frames_rx++;
                    ml->derp.last_recv_ms = ml_get_time_ms();
                    derp_frame_read(ml, &retry);
                } else if (ret == 0) {
                    break;  /* No more data / timeout */
                } else {
                    ESP_LOGW(TAG, "DERP read error: %d", ret);
                    ml_derp_disconnect(ml);
                    derp_attempt_failed(ml, &retry);
                    break;
                }
            }
        }

        /* ---- Phase 3: Sleep until there is work ---- */
#ifdef CONFIG_ML_ENABLE_CELLULAR
        /* AT sockets: no select() over the wake eventfd, so poll. */
        vTaskDelay(pdMS_TO_TICKS(1));
#else
        /* More TX than one drain takes, or plaintext TLS already decrypted (the
         * socket may be empty), is handled on the next pass without waiting. */
        if (ml->derp.connected && uxQueueMessagesWaiting(ml->derp_tx_queue) == 0 &&
            !mbedtls_ssl_check_pending(&ml->derp.ssl)) {
            uint64_t deadline = last_heartbeat_ms + DERP_HEARTBEAT_LOG_MS;
            if (last_status_ms + DERP_STATUS_LOG_MS < deadline) {
                deadline = last_status_ms + DERP_STATUS_LOG_MS;
            }
            uint64_t now = ml_get_time_ms();
            derp_wait_connected(ml, deadline > now ? (uint32_t)(deadline - now) : 0);
        }
#endif
    }

    ml_derp_disconnect(ml);
    ESP_LOGI(TAG, "DERP I/O task exiting");
    ml_task_exit(ml, ML_EVT_EXIT_DERP);
}

/* ============================================================================
 * DERP Connection Management (DERP I/O task)
 * ========================================================================== */

/* TCP connect bounded by ML_DERP_DIAL_TIMEOUT_MS: a blocking lwIP connect ignores
 * SO_SNDTIMEO and waits out every SYN retry (about 20 s) when SYNs are dropped. The
 * AT-command cellular bridge has its own connect timeout and keeps ml_connect. */
static int derp_dial(int sock, const struct sockaddr *addr, socklen_t len) {
    if (ml_at_socket_is_at_fd(sock)) return ml_connect(sock, addr, len);
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return connect(sock, addr, len);
    }
    int r = connect(sock, addr, len);
    if (r < 0 && errno == EINPROGRESS) {
        fd_set wr;
        FD_ZERO(&wr);
        FD_SET(sock, &wr);
        struct timeval tv = {
            .tv_sec = ML_DERP_DIAL_TIMEOUT_MS / 1000,
            .tv_usec = (ML_DERP_DIAL_TIMEOUT_MS % 1000) * 1000,
        };
        r = select(sock + 1, NULL, &wr, NULL, &tv);
        if (r == 1) {
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen);
            r = err ? -1 : 0;
            if (err) errno = err;
        } else {
            r = -1;
            errno = ETIMEDOUT;
        }
    }
    fcntl(sock, F_SETFL, flags);
    return r;
}

static bool derp_stopping(microlink_t *ml) {
    return (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) != 0;
}

/* Failure after the TLS contexts were set up: free them with the socket. */
static esp_err_t derp_connect_fail(microlink_t *ml, int sock) {
    mbedtls_ssl_free(&ml->derp.ssl);
    mbedtls_ssl_config_free(&ml->derp.ssl_conf);
    mbedtls_ctr_drbg_free(&ml->derp.ctr_drbg);
    mbedtls_entropy_free(&ml->derp.entropy);
    ml_close_sock(sock);
    ml->derp.sockfd = -1;
    return ESP_FAIL;
}

/* One TCP connection to one address, bounded by derp_dial(). */
static int derp_dial_addr(const struct sockaddr *addr, socklen_t len, int family) {
    int sock = ml_socket(family, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (derp_dial(sock, addr, len) < 0) {
        ESP_LOGW(TAG, "TCP connect failed: %d", errno);
        ml_close_sock(sock);
        return -1;
    }
    return sock;
}

/* One node, as derphttp dialNode: its IPv4 literal when the map gives one, else
 * its host name. The name lookup is the resolver's (it cannot be cancelled), so
 * unlike tailscaled it is not inside the dial timeout; every address it returns
 * is tried in turn. */
static int derp_dial_node(microlink_t *ml, const char *host, const char *ipv4, int port) {
    unsigned a, b, c, d;
    char extra;
    if (ipv4[0] && sscanf(ipv4, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) == 4 &&
        a <= 255 && b <= 255 && c <= 255 && d <= 255) {
        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_port = htons((uint16_t)port),
            .sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d),
        };
        return derp_dial_addr((const struct sockaddr *)&sa, sizeof(sa), AF_INET);
    }
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (ml_getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        ESP_LOGW(TAG, "DNS resolve failed for %s", host);
        if (res) ml_freeaddrinfo(res);
        return -1;
    }
    int sock = -1;
    for (struct addrinfo *ai = res; ai && sock < 0 && !derp_stopping(ml); ai = ai->ai_next) {
        sock = derp_dial_addr(ai->ai_addr, ai->ai_addrlen, ai->ai_family);
    }
    ml_freeaddrinfo(res);
    return sock;
}

esp_err_t ml_derp_connect(microlink_t *ml, uint16_t region) {
    /* Connect to `region` (the home region, ml_netcheck.c). As derphttp dialRegion:
     * every non-STUN-only node in turn; the attempt fails only when all do. Never a
     * region absent from the DERP map: without one, no connection. */
    typedef struct {
        char host[sizeof(((ml_derp_node_t *)0)->hostname)];
        char ipv4[sizeof(((ml_derp_node_t *)0)->ipv4)];
        int port;
    } node_copy_t;
    node_copy_t nodes[ML_MAX_DERP_NODES];   /* copies: coord may re-parse the map */
    int node_count = 0;
    /* Taken before connecting: a rebind or region change during the connect makes
     * this connection stale, and a pending reconnect request then replaces it. */
    uint32_t target_gen = ml->derp_target_gen;

    for (int i = 0; region != 0 && i < ml->derp_region_count; i++) {
        if (ml->derp_regions[i].region_id != region) continue;
        for (int n = 0; n < ml->derp_regions[i].node_count; n++) {
            const ml_derp_node_t *node = &ml->derp_regions[i].nodes[n];
            if (node->stun_only || !node->hostname[0]) continue;
            node_copy_t *nc = &nodes[node_count++];
            memcpy(nc->host, node->hostname, sizeof(nc->host));
            nc->host[sizeof(nc->host) - 1] = '\0';
            memcpy(nc->ipv4, node->ipv4, sizeof(nc->ipv4));
            nc->ipv4[sizeof(nc->ipv4) - 1] = '\0';
            nc->port = node->derp_port > 0 ? node->derp_port : ML_DERP_PORT;
        }
        break;
    }
    if (node_count == 0) {
        ESP_LOGW(TAG, "No DERP node for home region %u (map has %d regions)",
                 region, ml->derp_region_count);
        return ESP_FAIL;
    }

    int64_t t_derp_start = esp_timer_get_time();
    int64_t t_derp_dns = t_derp_start;      /* name lookups are part of each node's dial */
    char derp_host[sizeof(nodes[0].host)] = "";
    int sock = -1;
    for (int k = 0; k < node_count && sock < 0; k++) {
        if (derp_stopping(ml)) return ESP_FAIL;
        ESP_LOGI(TAG, "Connecting to DERP %s:%d (region %u)", nodes[k].host, nodes[k].port, region);
        sock = derp_dial_node(ml, nodes[k].host, nodes[k].ipv4, nodes[k].port);
        if (sock >= 0) memcpy(derp_host, nodes[k].host, sizeof(derp_host));
    }
    if (sock < 0) return ESP_FAIL;
    if (derp_stopping(ml)) {
        ml_close_sock(sock);
        return ESP_FAIL;
    }

    int64_t t_derp_tcp = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP TCP connect (with DNS): %lld ms", (t_derp_tcp - t_derp_dns) / 1000);

    /* TLS setup */
    mbedtls_ssl_init(&ml->derp.ssl);
    mbedtls_ssl_config_init(&ml->derp.ssl_conf);
    mbedtls_entropy_init(&ml->derp.entropy);
    mbedtls_ctr_drbg_init(&ml->derp.ctr_drbg);

    mbedtls_ctr_drbg_seed(&ml->derp.ctr_drbg, mbedtls_entropy_func,
                           &ml->derp.entropy, NULL, 0);

    mbedtls_ssl_config_defaults(&ml->derp.ssl_conf,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&ml->derp.ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&ml->derp.ssl_conf, mbedtls_ctr_drbg_random, &ml->derp.ctr_drbg);
    mbedtls_ssl_conf_read_timeout(&ml->derp.ssl_conf, DERP_CONNECT_TIMEOUT_MS);

    mbedtls_ssl_setup(&ml->derp.ssl, &ml->derp.ssl_conf);
    mbedtls_ssl_set_hostname(&ml->derp.ssl, derp_host);
    /* Store socket fd BEFORE setting bio.
     * Use custom BIO callbacks that route through ml_read_sock/ml_write_sock,
     * which transparently support both lwIP and AT socket backends.
     * Timeout is handled via SO_RCVTIMEO. */
    ml->derp.sockfd = sock;
    mbedtls_ssl_set_bio(&ml->derp.ssl, &ml->derp.sockfd,
                         ml_derp_bio_send, NULL, ml_derp_bio_recv_timeout);

    /* TLS handshake - socket has 10s SO_RCVTIMEO from connect phase. */
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ml->derp.ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "TLS handshake failed: %s", err_buf);
        return derp_connect_fail(ml, sock);
    }

    if (derp_stopping(ml)) return derp_connect_fail(ml, sock);
    int64_t t_derp_tls = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP TLS handshake: %lld ms", (t_derp_tls - t_derp_tcp) / 1000);
    ESP_LOGI(TAG, "TLS connected to DERP");

    /* HTTP Upgrade: GET /derp with Upgrade: DERP header */
    char upgrade_req[256];
    snprintf(upgrade_req, sizeof(upgrade_req),
             "GET /derp HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: Upgrade\r\n"
             "Upgrade: DERP\r\n"
             "\r\n",
             derp_host);

    ret = mbedtls_ssl_write(&ml->derp.ssl, (const uint8_t *)upgrade_req, strlen(upgrade_req));
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to send HTTP upgrade");
        return derp_connect_fail(ml, sock);
    }

    /* Read HTTP response byte-by-byte until \r\n\r\n to avoid over-reading
     * into the DERP binary frame stream (matching v1 approach) */
    {
        uint8_t resp_buf[512];
        int resp_len = 0;
        bool found_end = false;
        uint64_t http_start = ml_get_time_ms();

        while (resp_len < (int)sizeof(resp_buf) - 1) {
            if (derp_stopping(ml)) return derp_connect_fail(ml, sock);
            if (ml_get_time_ms() - http_start > DERP_CONNECT_TIMEOUT_MS) {
                ESP_LOGE(TAG, "HTTP upgrade response timeout");
                return derp_connect_fail(ml, sock);
            }

            ret = mbedtls_ssl_read(&ml->derp.ssl, resp_buf + resp_len, 1);
            if (ret < 0) {
                if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                    ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                    vTaskDelay(pdMS_TO_TICKS(10));
                    continue;
                }
                ESP_LOGE(TAG, "HTTP upgrade read failed: -0x%04x", -ret);
                return derp_connect_fail(ml, sock);
            }
            if (ret == 0) {
                ESP_LOGE(TAG, "Connection closed during HTTP upgrade");
                return derp_connect_fail(ml, sock);
            }
            resp_len++;

            /* Check for \r\n\r\n */
            if (resp_len >= 4 &&
                resp_buf[resp_len - 4] == '\r' && resp_buf[resp_len - 3] == '\n' &&
                resp_buf[resp_len - 2] == '\r' && resp_buf[resp_len - 1] == '\n') {
                found_end = true;
                break;
            }
        }

        resp_buf[resp_len] = '\0';

        if (!found_end || strstr((char *)resp_buf, "101") == NULL) {
            ESP_LOGE(TAG, "DERP upgrade rejected: %.100s", resp_buf);
            return derp_connect_fail(ml, sock);
        }
        ESP_LOGI(TAG, "HTTP 101 Switching Protocols received");
    }

    /* Match v1: O_NONBLOCK + SO_RCVTIMEO + SO_SNDTIMEO.
     * O_NONBLOCK makes read()/write() return at once (EAGAIN) instead of
     * blocking; lwIP ignores SO_RCVTIMEO for a nonblocking read, so the 100ms
     * value sets no read rhythm. The I/O task waits for data in select(). */
    {
        int flags = ml_fcntl(sock, F_GETFL, 0);
        if (flags >= 0) {
            ml_fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
        struct timeval io_tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
        ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &io_tv, sizeof(io_tv));
        ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &io_tv, sizeof(io_tv));
    }

    /* ========================================================
     * DERP Handshake: ServerKey -> ClientInfo -> ServerInfo
     * ======================================================== */

    /* Step 1: Read ServerKey frame header using reliable read helper */
    uint8_t frame_type;
    uint32_t frame_len;
    esp_err_t err = derp_recv_frame_header(ml, &frame_type, &frame_len, DERP_CONNECT_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read ServerKey frame header (err=%d)", err);
        return derp_connect_fail(ml, sock);
    }

    if (frame_type != DERP_FRAME_SERVER_KEY || frame_len < 40) {
        ESP_LOGE(TAG, "Expected ServerKey frame (0x01), got 0x%02x len=%lu",
                 frame_type, (unsigned long)frame_len);
        return derp_connect_fail(ml, sock);
    }

    /* Read and verify 8-byte magic */
    uint8_t magic[8];
    static const uint8_t DERP_MAGIC[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
    if (derp_tls_read_all(ml, magic, 8, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read ServerKey magic");
        return derp_connect_fail(ml, sock);
    }

    if (memcmp(magic, DERP_MAGIC, 8) != 0) {
        ESP_LOGE(TAG, "Invalid DERP magic: %02x%02x%02x%02x%02x%02x%02x%02x",
                 magic[0], magic[1], magic[2], magic[3],
                 magic[4], magic[5], magic[6], magic[7]);
        return derp_connect_fail(ml, sock);
    }
    ESP_LOGI(TAG, "DERP magic verified");

    /* Read 32-byte server public key */
    uint8_t derp_server_key[32];
    if (derp_tls_read_all(ml, derp_server_key, 32, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read server key");
        return derp_connect_fail(ml, sock);
    }

    ESP_LOGI(TAG, "DERP server key received (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             derp_server_key[0], derp_server_key[1], derp_server_key[2], derp_server_key[3],
             derp_server_key[4], derp_server_key[5], derp_server_key[6], derp_server_key[7]);

    /* Skip remaining bytes if frame_len > 40 */
    if (frame_len > 40) {
        uint8_t skip_buf[64];
        size_t remaining = frame_len - 40;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(skip_buf) ? sizeof(skip_buf) : remaining;
            if (derp_tls_read_all(ml, skip_buf, chunk, DERP_CONNECT_TIMEOUT_MS) < 0) break;
            remaining -= chunk;
        }
    }

    /* Step 2: Send ClientInfo frame (type 0x02)
     * Payload: [our_nodekey(32)][nonce(24)][nacl_box(JSON)] */
    {
        const char *client_info_json = "{\"Version\":2,\"CanAckPings\":true,\"IsProber\":false}";
        size_t json_len = strlen(client_info_json);

        /* Generate random nonce */
        uint8_t nonce[NACL_BOX_NONCEBYTES];
        esp_fill_random(nonce, NACL_BOX_NONCEBYTES);

        /* Encrypt JSON with NaCl box: our WG private key -> DERP server public key */
        size_t ciphertext_len = json_len + NACL_BOX_MACBYTES;
        uint8_t *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
            return derp_connect_fail(ml, sock);
        }

        if (nacl_box(ciphertext,
                     (const uint8_t *)client_info_json, json_len,
                     nonce,
                     derp_server_key,       /* recipient: DERP server */
                     ml->wg_private_key     /* sender: our WG node key */
                     ) != 0) {
            ESP_LOGE(TAG, "NaCl box encrypt failed");
            free(ciphertext);
            return derp_connect_fail(ml, sock);
        }

        /* Build ClientInfo frame payload: nodekey(32) + nonce(24) + ciphertext */
        size_t ci_payload_len = 32 + NACL_BOX_NONCEBYTES + ciphertext_len;
        uint8_t *ci_payload = malloc(ci_payload_len);
        if (!ci_payload) {
            free(ciphertext);
            return derp_connect_fail(ml, sock);
        }

        memcpy(ci_payload, ml->wg_public_key, 32);
        memcpy(ci_payload + 32, nonce, NACL_BOX_NONCEBYTES);
        memcpy(ci_payload + 32 + NACL_BOX_NONCEBYTES, ciphertext, ciphertext_len);
        free(ciphertext);

        ESP_LOGI(TAG, "DERP ClientInfo sent");

        /* Send ClientInfo frame */
        if (derp_write_frame(ml, DERP_FRAME_CLIENT_INFO, ci_payload, ci_payload_len) < 0) {
            ESP_LOGE(TAG, "Failed to send ClientInfo");
            free(ci_payload);
            return derp_connect_fail(ml, sock);
        }
        free(ci_payload);

        ESP_LOGI(TAG, "ClientInfo sent");
    }

    /* Step 3: Read ServerInfo frame (type 0x03) */
    ml->derp.server_info = false;
    {
        uint8_t si_type;
        uint32_t si_len;
        err = derp_recv_frame_header(ml, &si_type, &si_len, DERP_CONNECT_TIMEOUT_MS);
        if (err == ESP_OK && si_type == DERP_FRAME_SERVER_INFO && si_len > 0) {
            /* Read and discard ServerInfo payload */
            uint8_t *si_buf = malloc(si_len);
            if (si_buf) {
                ml->derp.server_info =
                    derp_tls_read_all(ml, si_buf, si_len, DERP_CONNECT_TIMEOUT_MS) == (int)si_len;
                free(si_buf);
            }
            ESP_LOGI(TAG, "ServerInfo received (discarded)");
        } else if (err != ESP_OK) {
            ESP_LOGW(TAG, "No ServerInfo frame (continuing anyway)");
        }
    }

    /* Send NotePreferred (type 0x07): this is our preferred DERP */
    {
        uint8_t preferred = 0x01;
        derp_write_frame(ml, DERP_FRAME_NOTE_PREFERRED, &preferred, 1);
    }

    /* Data-phase receive timeout. The socket is O_NONBLOCK, so a read never waits
     * for it; the I/O task sleeps in select() instead. */
    {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };  /* 200ms */
        ml_setsockopt(ml->derp.sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        mbedtls_ssl_conf_read_timeout(&ml->derp.ssl_conf, 200);
    }

    ml->derp.region = region;
    ml->derp.target_gen = target_gen;
    ml->derp.connected = true;
    ml->derp.last_recv_ms = ml_get_time_ms();
    xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECTED);

    int64_t t_derp_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP total: %lld ms (DNS=%lld, TCP=%lld, TLS=%lld, proto=%lld)",
             (t_derp_done - t_derp_start) / 1000,
             (t_derp_dns - t_derp_start) / 1000,
             (t_derp_tcp - t_derp_dns) / 1000,
             (t_derp_tls - t_derp_tcp) / 1000,
             (t_derp_done - t_derp_tls) / 1000);
    ESP_LOGI(TAG, "DERP handshake complete, connected");
    return ESP_OK;
}

void ml_derp_disconnect(microlink_t *ml) {
    ml->derp.connected = false;
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);

    if (ml->derp.sockfd >= 0) {
        mbedtls_ssl_close_notify(&ml->derp.ssl);
        mbedtls_ssl_free(&ml->derp.ssl);
        mbedtls_ssl_config_free(&ml->derp.ssl_conf);
        mbedtls_ctr_drbg_free(&ml->derp.ctr_drbg);
        mbedtls_entropy_free(&ml->derp.entropy);
        ml_close_sock(ml->derp.sockfd);
        ml->derp.sockfd = -1;
    }

    /* Drain TX queue */
    ml_derp_tx_item_t item;
    while (xQueueReceive(ml->derp_tx_queue, &item, 0) == pdTRUE) {
        free(item.data);
    }

    ESP_LOGI(TAG, "DERP disconnected");
}
