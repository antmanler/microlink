/**
 * @file microlink.c
 * @brief MicroLink v2 - Public API and Task Orchestration
 *
 * Creates all FreeRTOS tasks, queues, and event groups.
 * Provides the public API that the application calls.
 */

#include "microlink_internal.h"
#include "ml_register.h"
#include "esp_log.h"
#include "esp_heap_caps.h"  /* [ambient-mod] PSRAM task stacks */
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include "lwip/sockets.h"

#ifdef CONFIG_ML_ENABLE_CELLULAR
#include "ml_cellular.h"
#endif

static const char *TAG = "microlink";

/* NVS keys */
#define NVS_NAMESPACE       "microlink"
#define NVS_KEY_MACHINE_PRI "machine_pri"
#define NVS_KEY_MACHINE_PUB "machine_pub"
#define NVS_KEY_WG_PRI      "wg_private"
#define NVS_KEY_WG_PUB      "wg_public"
#define NVS_KEY_DISCO_PRI   "disco_pri"
#define NVS_KEY_DISCO_PUB   "disco_pub"
#define NVS_KEY_WG_OLD_PUB  "wg_old_pub"   /* expired node public key while a rotation is pending */

/* X25519 from x25519.h */
#include "x25519.h"
/* ============================================================================
 * [ambient-mod] Move selected task stacks to PSRAM
 * ============================================================================
 *
 * Problem: these four task stacks total 42KB (net_io 8 + derp_tx 14 + coord 12
 * + wg_mgr 8), while the rig-hover host project has only about 59KB of free
 * internal heap. microlink_start reports "Failed to create coord task", retries
 * every 5 seconds, and never joins the tailnet.
 *
 * Why **selected** rather than all tasks: the second attempt moved every stack
 * and put the device into a reboot loop:
 *     assert failed: spi_flash_disable_interrupts_caches_and_other_cpu
 *                    cache_utils.c:127 (esp_task_stack_is_sane_cache_disabled())
 * ESP-IDF has a hard constraint: a task whose stack resides in PSRAM cannot run
 * any operation that disables the flash cache (NVS / SPI flash), because PSRAM
 * access itself requires the cache.
 *
 * Call-graph analysis, including indirect calls rather than only grepping task bodies:
 *   ml_net_io_task   does not touch flash  → PSRAM stack
 *   ml_derp_tx_task  does not touch flash  → PSRAM stack
 *   ml_coord_task    does not touch flash  → PSRAM stack
 *   ml_wg_mgr_task   does: process_peer_updates → ml_peer_nvs_* (ml_peer_nvs.c)
 *                                                → stack stays in internal RAM
 *
 * Net effect: internal RAM demand falls from 42KB to 8KB.
 *
 * Unit trap: xTaskCreate* stack parameters are in **bytes**; xTaskCreateStatic*
 * parameters are in **words**. Omitting /sizeof(StackType_t) makes the stack four
 * times too small, causing random stack overflows that are harder to diagnose than
 * OOM. TCBs always remain in internal RAM because FreeRTOS accesses them in
 * critical sections.
 */
#define ML_CREATE_TASK_PSRAM(fn, tname, stackbytes, prio, field, core)                  \
    do {                                                                                \
        static StaticTask_t tcb_##field;                                                \
        StackType_t *stk_##field =                                                      \
            (StackType_t *)heap_caps_malloc((stackbytes), MALLOC_CAP_SPIRAM);           \
        if (stk_##field == NULL) {                                                      \
            ESP_LOGE(TAG, "Failed to alloc %s stack (%d B) in PSRAM", tname,            \
                     (int)(stackbytes));                                                \
            return ESP_FAIL;                                                            \
        }                                                                               \
        ml->field = xTaskCreateStaticPinnedToCore(                                      \
            fn, tname, (stackbytes) / sizeof(StackType_t), ml, prio,                    \
            stk_##field, &tcb_##field, core);                                           \
        if (ml->field == NULL) {                                                        \
            ESP_LOGE(TAG, "Failed to create %s task", tname);                           \
            heap_caps_free(stk_##field);                                                \
            return ESP_FAIL;                                                            \
        }                                                                               \
        ml->field##_stack = stk_##field;  /* freed by microlink_stop() */               \
    } while (0)


/* ============================================================================
 * Key Management (loaded once at init, read-only after)
 * ========================================================================== */

static void generate_keypair(uint8_t *private_key, uint8_t *public_key) {
    esp_fill_random(private_key, 32);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    x25519_base(public_key, private_key, 1);
}

/* Write one 32-byte key; keeps the first error seen. */
static esp_err_t set_blob32(nvs_handle_t nvs, const char *key, const uint8_t *value,
                            esp_err_t first_error) {
    esp_err_t e = nvs_set_blob(nvs, key, value, 32);
    return first_error != ESP_OK ? first_error : e;
}

static esp_err_t load_or_generate_keys(microlink_t *ml) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        if (ml->interactive) {
            /* Interactive login needs a node identity that survives reboot:
             * ephemeral keys would register a new node on every boot. */
            ESP_LOGE(TAG, "NVS open failed (%d): identity cannot persist", err);
            return err;
        }
        ESP_LOGW(TAG, "NVS open failed (%d), generating ephemeral keys", err);
        generate_keypair(ml->machine_private_key, ml->machine_public_key);
        generate_keypair(ml->wg_private_key, ml->wg_public_key);
        generate_keypair(ml->disco_private_key, ml->disco_public_key);
        return ESP_OK;
    }

    size_t key_len = 32;
    bool need_save = false;

    /* Machine key */
    if (nvs_get_blob(nvs, NVS_KEY_MACHINE_PRI, ml->machine_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->machine_private_key, ml->machine_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new machine key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_MACHINE_PUB, ml->machine_public_key, &key_len);
    }

    /* WireGuard key */
    key_len = 32;
    if (nvs_get_blob(nvs, NVS_KEY_WG_PRI, ml->wg_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->wg_private_key, ml->wg_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new WireGuard key");
    } else {
        /* The private half is authoritative. A node key rotation interrupted
         * between its two NVS writes would otherwise leave a mismatched pair. */
        uint8_t derived_pub[32];
        x25519_base(derived_pub, ml->wg_private_key, 1);
        key_len = 32;
        if (nvs_get_blob(nvs, NVS_KEY_WG_PUB, ml->wg_public_key, &key_len) != ESP_OK ||
            memcmp(derived_pub, ml->wg_public_key, 32) != 0) {
            memcpy(ml->wg_public_key, derived_pub, 32);
            need_save = true;
        }
    }

    /* DISCO key */
    key_len = 32;
    if (nvs_get_blob(nvs, NVS_KEY_DISCO_PRI, ml->disco_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->disco_private_key, ml->disco_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new DISCO key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_DISCO_PUB, ml->disco_public_key, &key_len);
    }

    if (need_save) {
        esp_err_t save_err = ESP_OK;
        save_err = set_blob32(nvs, NVS_KEY_MACHINE_PRI, ml->machine_private_key, save_err);
        save_err = set_blob32(nvs, NVS_KEY_MACHINE_PUB, ml->machine_public_key, save_err);
        save_err = set_blob32(nvs, NVS_KEY_WG_PRI, ml->wg_private_key, save_err);
        save_err = set_blob32(nvs, NVS_KEY_WG_PUB, ml->wg_public_key, save_err);
        save_err = set_blob32(nvs, NVS_KEY_DISCO_PRI, ml->disco_private_key, save_err);
        save_err = set_blob32(nvs, NVS_KEY_DISCO_PUB, ml->disco_public_key, save_err);
        esp_err_t commit_err = nvs_commit(nvs);
        if (save_err == ESP_OK) save_err = commit_err;
        if (save_err != ESP_OK) {
            ESP_LOGE(TAG, "Saving keys to NVS failed (%d)", save_err);
            if (ml->interactive) {
                nvs_close(nvs);
                return save_err;
            }
        } else {
            ESP_LOGI(TAG, "Keys saved to NVS");
        }
    } else {
        ESP_LOGI(TAG, "Keys loaded from NVS");
    }

    /* Rotation pending? The expired key is sent as OldNodeKey until a register
     * succeeds. Equal to the current key means a torn rotation write: ignore. */
    key_len = 32;
    ml->old_node_valid = (nvs_get_blob(nvs, NVS_KEY_WG_OLD_PUB, ml->old_node_pub, &key_len) == ESP_OK &&
                          key_len == 32 &&
                          memcmp(ml->old_node_pub, ml->wg_public_key, 32) != 0);
    if (ml->old_node_valid) {
        ESP_LOGW(TAG, "Node key rotation pending (re-register with OldNodeKey)");
    }

    nvs_close(nvs);
    return ESP_OK;
}

/* ============================================================================
 * cJSON PSRAM Hooks
 * ========================================================================== */

static void *cjson_psram_malloc(size_t size) {
    return ml_psram_malloc(size);
}

/* ============================================================================
 * Factory Reset
 * ========================================================================== */

esp_err_t microlink_factory_reset(void) {
    esp_err_t err;

    /* Erase key namespace */
    nvs_handle_t nvs;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG, "Factory reset: keys erased");
    }

    /* Erase cached peers */
    ml_peer_nvs_init();
    ml_peer_nvs_clear();
    ml_peer_nvs_deinit();

    ESP_LOGI(TAG, "Factory reset complete");
    return ESP_OK;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

microlink_t *microlink_init(const microlink_config_t *config) {
    if (!config) {
        ESP_LOGE(TAG, "Invalid config");
        return NULL;
    }

    /* Route cJSON to PSRAM */
    cJSON_Hooks hooks = {
        .malloc_fn = cjson_psram_malloc,
        .free_fn = free
    };
    cJSON_InitHooks(&hooks);

    /* Allocate context from PSRAM */
    microlink_t *ml = ml_psram_calloc(1, sizeof(microlink_t));
    if (!ml) {
        ESP_LOGE(TAG, "Failed to allocate context");
        return NULL;
    }

    /* Copy config. The auth key is optional: without it the node logs in
     * interactively and its identity must persist. */
    ml->config = *config;
    ml->interactive = !(config->auth_key && config->auth_key[0]);
    portMUX_INITIALIZE(&ml->id_lock);
    ml_peer_updates_init(ml);   /* before any path can reach stop or destroy */
    if (ml->config.max_peers == 0) ml->config.max_peers = ML_MAX_PEERS;
    if (ml->config.max_peers > ML_MAX_PEERS) ml->config.max_peers = ML_MAX_PEERS;
    ml->config.enable_derp = true;  /* Always need DERP for relay */

    ml->state = ML_STATE_IDLE;
    ml->coord_sock = -1;
    ml->disco_sock4 = -1;
    ml->disco_sock6 = -1;
    ml->stun_sock = -1;
    ml->stun_sock6 = -1;
    ml->derp.sockfd = -1;
    ml->derp_wake_fd = -1;

    /* Resolve timing (0 = use defaults from #defines) */
    ml->t_disco_heartbeat_ms = ml->config.disco_heartbeat_ms ? ml->config.disco_heartbeat_ms : ML_DISCO_HEARTBEAT_MS;
    ml->t_stun_interval_ms = ml->config.stun_interval_ms ? ml->config.stun_interval_ms : ML_STUN_RESTUN_INTERVAL_MS;
    ml->t_ctrl_watchdog_ms = ml->config.ctrl_watchdog_ms ? ml->config.ctrl_watchdog_ms : ML_CTRL_WATCHDOG_MS;

    /* Apply Kconfig priority peer if set and app didn't provide one */
    if (ml->config.priority_peer_ip == 0 && strlen(CONFIG_ML_PRIORITY_PEER_IP) > 0) {
        ml->config.priority_peer_ip = microlink_parse_ip(CONFIG_ML_PRIORITY_PEER_IP);
        if (ml->config.priority_peer_ip) {
            ESP_LOGI(TAG, "Priority peer set from Kconfig");
        }
    }

    /* Load or generate persistent keys. Fails only in interactive mode when NVS
     * cannot hold them; the handle then reports ML_ERR_STORAGE (see the end). */
    bool storage_failed = (load_or_generate_keys(ml) != ESP_OK);

    if (!storage_failed) {
        /* Initialize peer NVS cache */
        ml_peer_nvs_init();

        /* Initialize HTTP config server (loads NVS peer allowlist + settings) */
        ml->config_httpd = ml_config_httpd_init();
    }

    /* Override config with NVS-saved settings (web UI save → restart flow).
     * NVS settings take priority over Kconfig defaults.  Strings are copied
     * into ml->nvs_* buffers so the const char* pointers remain valid. */
    if (ml->config_httpd) {
        const char *nvs_auth = ml_config_get_auth_key(ml->config_httpd);
        if (nvs_auth) {
            strncpy(ml->nvs_auth_key, nvs_auth, sizeof(ml->nvs_auth_key) - 1);
            ml->config.auth_key = ml->nvs_auth_key;
            ESP_LOGI(TAG, "Auth key overridden from NVS (len=%d)", (int)strlen(nvs_auth));
        }
        /* Device name: full name takes priority, then prefix+MAC, then Kconfig */
        const char *nvs_full_name = ml_config_get_device_name_full(ml->config_httpd);
        if (nvs_full_name) {
            /* Full custom hostname (e.g. "sensor-tailscale") */
            strncpy(ml->nvs_device_name, nvs_full_name, sizeof(ml->nvs_device_name) - 1);
            ml->config.device_name = ml->nvs_device_name;
            ESP_LOGI(TAG, "Device name overridden from NVS (full)");
        } else {
            const char *nvs_prefix = ml_config_get_device_prefix(ml->config_httpd);
            if (nvs_prefix) {
                /* Device name = prefix + MAC suffix (e.g. "sensor-a1b2c3") */
                uint8_t mac[6];
                esp_read_mac(mac, ESP_MAC_WIFI_STA);
                snprintf(ml->nvs_device_name, sizeof(ml->nvs_device_name),
                         "%s-%02x%02x%02x", nvs_prefix, mac[3], mac[4], mac[5]);
                ml->config.device_name = ml->nvs_device_name;
                ESP_LOGI(TAG, "Device name overridden from NVS (prefix + MAC)");
            }
        }

        /* v2 overrides */
        uint8_t nvs_max = ml_config_get_max_peers(ml->config_httpd);
        if (nvs_max > 0 && nvs_max <= ML_MAX_PEERS) {
            ml->config.max_peers = nvs_max;
            ESP_LOGI(TAG, "Max peers overridden from NVS: %d", nvs_max);
        }
        uint16_t nvs_hb = ml_config_get_disco_heartbeat_ms(ml->config_httpd);
        if (nvs_hb > 0 && nvs_hb <= 60000) {
            ml->config.disco_heartbeat_ms = nvs_hb;
            ml->t_disco_heartbeat_ms = nvs_hb;
            ESP_LOGI(TAG, "DISCO heartbeat overridden from NVS: %dms", nvs_hb);
        }
        uint32_t nvs_pip = ml_config_get_priority_peer_ip(ml->config_httpd);
        if (nvs_pip > 0) {
            ml->config.priority_peer_ip = nvs_pip;
            ESP_LOGI(TAG, "Priority peer overridden from NVS");
        }
        const char *nvs_ctrl = ml_config_get_ctrl_host(ml->config_httpd);
        if (nvs_ctrl) {
            strncpy(ml->ctrl_host, nvs_ctrl, sizeof(ml->ctrl_host) - 1);
            ESP_LOGI(TAG, "Control plane overridden from NVS: %s", ml->ctrl_host);
        }
        ml->debug_flags = ml_config_get_debug_flags(ml->config_httpd);
        if (ml->debug_flags) {
            ESP_LOGI(TAG, "Debug flags from NVS: 0x%02x", ml->debug_flags);
        }
    }

    ml->interactive = !(ml->config.auth_key && ml->config.auth_key[0]);

    /* Create event group */
    ml->events = xEventGroupCreate();
    if (!ml->events) {
        ESP_LOGE(TAG, "Failed to create event group");
        free(ml);
        return NULL;
    }

    /* Create queues */
    ml->derp_tx_queue = xQueueCreate(ML_DERP_TX_QUEUE_DEPTH, sizeof(ml_derp_tx_item_t));
    ml->disco_rx_queue = xQueueCreate(ML_DISCO_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->wg_rx_queue = xQueueCreate(ML_WG_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->stun_rx_queue = xQueueCreate(ML_STUN_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->coord_cmd_queue = xQueueCreate(ML_COORD_CMD_QUEUE_DEPTH, sizeof(ml_coord_cmd_t));

    if (!ml->derp_tx_queue || !ml->disco_rx_queue || !ml->wg_rx_queue ||
        !ml->stun_rx_queue || !ml->coord_cmd_queue) {
        ESP_LOGE(TAG, "Failed to create queues");
        microlink_destroy(ml);
        return NULL;
    }

    /* Wakes the DERP I/O task on derp_tx_queue sends. Lives as long as the queue:
     * microlink_send() may enqueue whenever the instance exists. */
    if (ml_derp_wake_init(ml) != ESP_OK) {
        microlink_destroy(ml);
        return NULL;
    }

    if (storage_failed) {
        ml->state = ML_STATE_ERROR;
        ml->last_error = ML_ERR_STORAGE;
        ESP_LOGE(TAG, "MicroLink initialized in ERROR state (storage); start is refused");
        return ml;
    }

    ESP_LOGI(TAG, "MicroLink v2 initialized (max_peers=%d)", ml->config.max_peers);
    return ml;
}

esp_err_t microlink_start(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (ml->state != ML_STATE_IDLE) {
        ESP_LOGW(TAG, "Already started (state=%d)", ml->state);
        return ESP_ERR_INVALID_STATE;
    }

    /* A previous stop left these set; the new tasks must not see them. */
    xEventGroupClearBits(ml->events, ML_EVT_SHUTDOWN_REQUEST | ML_EVT_EXIT_NET_IO |
                         ML_EVT_EXIT_DERP | ML_EVT_EXIT_COORD | ML_EVT_EXIT_WG_MGR |
                         ML_EVT_COORD_REGISTERED | ML_EVT_DERP_CONNECTED |
                         ML_EVT_DERP_RECONNECT | ML_EVT_DERP_CONNECT_REQ |
                         ML_EVT_PRIORITY_CLEARED);
    /* Region exclusions from the last run (maybe our own outage) do not carry over. */
    ml_netcheck_forget_derp_failures(ml);

    ml->state = ML_STATE_WIFI_WAIT;

    /* Set WiFi TX power if configured */
    if (ml->config.wifi_tx_power_dbm > 0) {
        int8_t power_quarter_dbm = ml->config.wifi_tx_power_dbm * 4;
        esp_wifi_set_max_tx_power(power_quarter_dbm);
        ESP_LOGI(TAG, "WiFi TX power set to %d dBm", ml->config.wifi_tx_power_dbm);
    }

#ifdef CONFIG_ML_ZERO_COPY_WG
    /* Zero-copy mode: raw lwIP PCB replaces BSD socket for DISCO/WG UDP.
     * WG packets go directly to wireguardif_network_rx() from tcpip_thread.
     * DISCO packets go to SPSC ring buffer, STUN to existing queue. */
    if (ml_zerocopy_init(ml) != ESP_OK) {
        ESP_LOGE(TAG, "Zero-copy init failed, falling back to BSD socket");
        goto bsd_socket_fallback;
    }
    ESP_LOGI(TAG, "Zero-copy WG mode active (high-throughput)");
    goto skip_bsd_socket;

bsd_socket_fallback:
#endif
    /* Create DISCO/magicsock UDP socket (port 51820 = WireGuard standard)
     * This is the single socket for ALL direct UDP traffic: DISCO pings/pongs,
     * CallMeMaybe probes, and WireGuard encrypted data.
     * Matches v1 microlink_disco_init() and tailscale's pconn4. */
    ml->disco_sock4 = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->disco_sock4 >= 0) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(51820),
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            ESP_LOGW(TAG, "Failed to bind port 51820 (errno=%d), trying ephemeral", errno);
            bind_addr.sin_port = 0;
            ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        }

        /* Mark packets as DSCP 46 (Expedited Forwarding) → WMM AC_VO.
         * WiFi APs with WMM use shorter contention windows for voice-priority
         * traffic, reducing jitter on WireGuard/DISCO UDP packets. */
        int tos = 0xB8;  /* DSCP 46 = EF, TOS byte = 46 << 2 = 184 */
        setsockopt(ml->disco_sock4, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

        /* Set non-blocking for select() in net_io */
        int flags = ml_fcntl(ml->disco_sock4, F_GETFL, 0);
        ml_fcntl(ml->disco_sock4, F_SETFL, flags | O_NONBLOCK);

        /* Record the actual bound port (getsockname not wrapped — AT sockets use stored port) */
        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(ml->disco_sock4, (struct sockaddr *)&local_addr, &addr_len);
        ml->disco_local_port = ntohs(local_addr.sin_port);
        ESP_LOGI(TAG, "DISCO/magicsock UDP socket bound to port %d", ml->disco_local_port);
    } else {
        ESP_LOGE(TAG, "Failed to create DISCO socket: errno=%d", errno);
    }
#ifdef CONFIG_ML_ZERO_COPY_WG
skip_bsd_socket:
    ;
#endif

    /* Create tasks — [ambient-mod] The first three stacks live in PSRAM; wg_mgr
     * touches NVS and must remain internal. */
    BaseType_t ret;

    ML_CREATE_TASK_PSRAM(ml_net_io_task, "ml_net_io", ML_TASK_NET_IO_STACK,
                         ML_TASK_NET_IO_PRIO, net_io_task, ML_TASK_NET_IO_CORE);
    ML_CREATE_TASK_PSRAM(ml_derp_tx_task, "ml_derp_tx", ML_TASK_DERP_TX_STACK,
                         ML_TASK_DERP_TX_PRIO, derp_tx_task, ML_TASK_DERP_TX_CORE);
    ML_CREATE_TASK_PSRAM(ml_coord_task, "ml_coord", ML_TASK_COORD_STACK,
                         ML_TASK_COORD_PRIO, coord_task, ML_TASK_COORD_CORE);

    /* wg_mgr calls process_peer_updates → ml_peer_nvs_*, which disables the
     * flash cache, so its stack must remain in internal RAM. */
    ret = xTaskCreatePinnedToCore(ml_wg_mgr_task, "ml_wg_mgr", ML_TASK_WG_MGR_STACK,
                                   ml, ML_TASK_WG_MGR_PRIO, &ml->wg_mgr_task, ML_TASK_WG_MGR_CORE);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create wg_mgr task");
        return ESP_FAIL;
    }

    /* WiFi is expected to be connected before microlink_start() is called.
     * Signal the event so coord/wg_mgr tasks proceed immediately. */
    xEventGroupSetBits(ml->events, ML_EVT_WIFI_CONNECTED);

    /* Signal coord task to start connecting */
    ml_coord_cmd_t cmd = ML_CMD_CONNECT;
    xQueueSend(ml->coord_cmd_queue, &cmd, 0);

    /* Start HTTP config server (binds port 80, serves config page + REST API).
     * Without CONFIG_ML_CONFIG_HTTPD only the server is skipped: ml_config_httpd_init()
     * already loaded the NVS settings above, so a provisioned device runs normally
     * and keeps the ~7-8 KB of internal RAM the httpd task would pin. */
#ifdef CONFIG_ML_CONFIG_HTTPD
    if (ml->config_httpd) {
        ml_config_httpd_start(ml->config_httpd, ml);
    }
#endif

    ESP_LOGI(TAG, "All tasks started");
    return ESP_OK;
}

esp_err_t microlink_rebind(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (ml->state == ML_STATE_IDLE) return ESP_ERR_INVALID_STATE;

    ESP_LOGI(TAG, "=== Rebinding to new network interface ===");

    /* DERP connections from here on are on the new network (see derp_target_gen). */
    ml->derp_target_gen++;

    /* Step 1: Invalidate socket FDs FIRST, then delay to let net_io_task's
     * select() cycle complete (50ms timeout). Only THEN close the old FDs.
     * Closing a socket while another thread has it in select() deadlocks
     * on lwIP's global socket lock. */
    int old_disco = ml->disco_sock4;
    int old_stun = ml->stun_sock;
    int old_stun6 = ml->stun_sock6;

    /* Invalidate — net_io_task will skip these on next iteration */
    ml->disco_sock4 = -1;
    ml->stun_sock = -1;
    ml->stun_sock6 = -1;

    /* Wait for net_io_task select() to cycle out (50ms timeout + margin) */
    vTaskDelay(pdMS_TO_TICKS(100));

    /* Now safe to close the old FDs */
    if (old_disco >= 0) ml_close_sock(old_disco);
    if (old_stun >= 0) ml_close_sock(old_stun);
    if (old_stun6 >= 0) ml_close_sock(old_stun6);
    ESP_LOGI(TAG, "Rebind: closed DISCO + STUN sockets");

    /* Step 2: Signal coord to reconnect. ML_CMD_FORCE_RECONNECT closes
     * the coord socket, resets Noise state, and re-enters the
     * STUN → DNS → TCP → Noise → Register → MapRequest flow.
     * Peers and WG state are preserved. */
    xEventGroupClearBits(ml->events, ML_EVT_COORD_REGISTERED);
    ml_coord_cmd_t cmd = ML_CMD_REBIND;     /* also drops the old STUN endpoint */
    xQueueSend(ml->coord_cmd_queue, &cmd, pdMS_TO_TICKS(100));

    /* Step 3: Signal DERP to reconnect. ML_EVT_DERP_RECONNECT triggers
     * derp_tx_task to close TLS, then reconnect with full handshake.
     * Pending TX packets are drained but WG state is preserved. */
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);
    xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
    ml_derp_wake(ml);
    ESP_LOGI(TAG, "Rebind: signaled coord + DERP to reconnect");

    /* Step 4: Brief delay for coord/DERP to process reconnect signals */
    vTaskDelay(pdMS_TO_TICKS(200));

    /* Step 5: Recreate DISCO UDP socket on the new interface */
#ifdef CONFIG_ML_ZERO_COPY_WG
    ml_zerocopy_deinit(ml);
    if (ml_zerocopy_init(ml) == ESP_OK) {
        ESP_LOGI(TAG, "Rebind: zero-copy DISCO PCB recreated");
        goto rebind_wg_update;
    }
    ESP_LOGW(TAG, "Rebind: zero-copy init failed, using BSD socket fallback");
#endif
    ml->disco_sock4 = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->disco_sock4 >= 0) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(51820),
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            bind_addr.sin_port = 0;
            ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        }
        int tos = 0xB8;
        setsockopt(ml->disco_sock4, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        int flags = ml_fcntl(ml->disco_sock4, F_GETFL, 0);
        ml_fcntl(ml->disco_sock4, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(ml->disco_sock4, (struct sockaddr *)&local_addr, &addr_len);
        ml->disco_local_port = ntohs(local_addr.sin_port);
        ESP_LOGI(TAG, "Rebind: DISCO socket rebound to port %d", ml->disco_local_port);
    } else {
        ESP_LOGE(TAG, "Rebind: failed to create DISCO socket: errno=%d", errno);
    }

#ifdef CONFIG_ML_ZERO_COPY_WG
rebind_wg_update:
#endif
    /* Step 6: Update WG output mode for new transport */
    ml_wg_mgr_update_transport(ml);

    ESP_LOGI(TAG, "=== Rebind complete — waiting for coord+DERP reconnect ===");
    return ESP_OK;
}

/* Delete a task that stopped through ml_task_exit() (it is suspended, or about to
 * be), then free its PSRAM stack. */
static void reap_task(TaskHandle_t *task, StackType_t **stack) {
    if (*task) {
        while (eTaskGetState(*task) != eSuspended) vTaskDelay(1);
        vTaskDelete(*task);
        *task = NULL;
    }
    if (stack && *stack) {
        heap_caps_free(*stack);
        *stack = NULL;
    }
}

esp_err_t microlink_stop(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    /* From a library task (state_cb runs on coord) the wait below never ends. */
    if (ml_is_library_task(ml, xTaskGetCurrentTaskHandle())) {
        ESP_LOGE(TAG, "microlink_stop() called from a MicroLink task: refused");
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Stopping...");
    xEventGroupSetBits(ml->events, ML_EVT_SHUTDOWN_REQUEST);
    /* End the DERP and wg_mgr sleeps (select() and task notification). */
    ml_derp_wake(ml);
    ml_wg_mgr_wake(ml);
    /* End a netcheck round blocked on stun_rx_queue (an empty item, see ml_coord.c). */
    if (ml->stun_rx_queue) {
        ml_rx_packet_t wake = {0};
        xQueueSend(ml->stun_rx_queue, &wake, 0);
    }
    /* End coord's reconnect backoff wait on its command queue. Coord keeps draining
     * the queue until it exits, so a full queue only delays the wake-up. */
    if (ml->coord_cmd_queue && ml->coord_task) {
        ml_coord_cmd_t wake_cmd = ML_CMD_SHUTDOWN_WAKE;
        while (!(xEventGroupGetBits(ml->events) & ML_EVT_EXIT_COORD) &&
               xQueueSend(ml->coord_cmd_queue, &wake_cmd, 1) != pdTRUE) {
        }
    }

    /* Wait for tasks to exit (they check ML_EVT_SHUTDOWN_REQUEST). Each sets its
     * exit bit and suspends itself (ml_task_exit); then it is deleted here. Sockets
     * and queues are released below, so this waits as long as a task needs. */
    EventBits_t exit_bits = 0;
    if (ml->net_io_task) exit_bits |= ML_EVT_EXIT_NET_IO;
    if (ml->derp_tx_task) exit_bits |= ML_EVT_EXIT_DERP;
    if (ml->coord_task) exit_bits |= ML_EVT_EXIT_COORD;
    if (ml->wg_mgr_task) exit_bits |= ML_EVT_EXIT_WG_MGR;
    if (exit_bits) {
        xEventGroupWaitBits(ml->events, exit_bits, pdFALSE, pdTRUE, portMAX_DELAY);
    }
    /* Remove the zero-copy PCB before deleting wg_mgr: its receive callback (tcpip
     * thread) notifies wg_mgr_task, which must not be a deleted task. */
#ifdef CONFIG_ML_ZERO_COPY_WG
    ml_zerocopy_deinit(ml);
#endif
    reap_task(&ml->net_io_task, &ml->net_io_task_stack);
    reap_task(&ml->derp_tx_task, &ml->derp_tx_task_stack);
    reap_task(&ml->coord_task, &ml->coord_task_stack);
    reap_task(&ml->wg_mgr_task, NULL);

    /* Updates wg_mgr never took belong to this session; the next one starts from
     * a full netmap. Freed here, so the list does not grow across stop and start. */
    ml_peer_updates_flush(ml);

    /* Stop HTTP config server */
    if (ml->config_httpd) {
        ml_config_httpd_stop(ml->config_httpd);
    }

    /* Close sockets */
    if (ml->disco_sock4 >= 0) { ml_close_sock(ml->disco_sock4); ml->disco_sock4 = -1; }
    if (ml->stun_sock >= 0) { ml_close_sock(ml->stun_sock); ml->stun_sock = -1; }
    if (ml->stun_sock6 >= 0) { ml_close_sock(ml->stun_sock6); ml->stun_sock6 = -1; }

    ml_set_auth_url(ml, NULL);   /* a pending login does not survive stop */
    ml->state = ML_STATE_IDLE;
    ESP_LOGI(TAG, "Stopped");
    return ESP_OK;
}

esp_err_t microlink_destroy(microlink_t *ml) {
    if (!ml) return ESP_OK;

    /* A refused stop (from a MicroLink task) leaves the tasks running: free nothing. */
    esp_err_t err = microlink_stop(ml);
    if (err != ESP_OK) return err;

    /* Deinitialize peer NVS */
    ml_peer_nvs_deinit();

    /* Deinitialize HTTP config server */
    if (ml->config_httpd) {
        ml_config_httpd_deinit(ml->config_httpd);
        ml->config_httpd = NULL;
    }

    /* Delete queues */
    if (ml->derp_tx_queue) vQueueDelete(ml->derp_tx_queue);
    if (ml->disco_rx_queue) vQueueDelete(ml->disco_rx_queue);
    if (ml->wg_rx_queue) vQueueDelete(ml->wg_rx_queue);
    if (ml->stun_rx_queue) vQueueDelete(ml->stun_rx_queue);
    if (ml->coord_cmd_queue) vQueueDelete(ml->coord_cmd_queue);
    ml_derp_wake_deinit(ml);
    /* Pending peer updates were freed by microlink_stop() above. */

    /* Delete event group */
    if (ml->events) vEventGroupDelete(ml->events);

    /* Clear keys and the login URL from memory */
    ml_set_auth_url(ml, NULL);
    memset(ml->machine_private_key, 0, 32);
    memset(ml->wg_private_key, 0, 32);
    memset(ml->disco_private_key, 0, 32);

    free(ml);
    ESP_LOGI(TAG, "Destroyed");
    return ESP_OK;
}

/* ============================================================================
 * Identity: node key rotation (DESIGN section 7 item 8 / section 12)
 *
 * NVS access disables the flash cache, which a task with a PSRAM stack must
 * never trigger (see ML_CREATE_TASK_PSRAM). The coord task is such a task, so
 * its two NVS operations run on a short-lived helper task with an internal
 * stack. The stack size is that of the wg_mgr task, the existing NVS user.
 * ========================================================================== */

typedef enum { NVS_JOB_ROTATE, NVS_JOB_CLEAR_OLD } nvs_job_op_t;

/* One job lives on the heap and belongs to the waiter. The helper writes `result` and
 * gives `done` as its last act on the job, and the waiter blocks on `done` until then
 * (no timeout), so the job outlives every write the helper makes. `done` is private to
 * the job: no other code can wake the waiter early, unlike the task's own notification. */
typedef struct {
    nvs_job_op_t op;
    uint8_t old_pub[32];
    uint8_t new_priv[32];
    uint8_t new_pub[32];
    SemaphoreHandle_t done;
    esp_err_t result;
} nvs_job_t;

static nvs_job_t *nvs_job_new(nvs_job_op_t op) {
    /* Internal RAM: the helper's NVS calls run with the flash cache off. */
    nvs_job_t *job = heap_caps_calloc(1, sizeof(*job), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (job) job->op = op;
    return job;
}

static void nvs_job_free(nvs_job_t *job) {
    if (job) ml_register_secure_free(job, sizeof(*job));   /* holds the new private key */
}

static esp_err_t nvs_job_run_now(const nvs_job_t *job) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    if (job->op == NVS_JOB_ROTATE) {
        /* Order matters: the old public key first, so an interruption never
         * leaves a new private key without the key it replaces. A private key
         * written without its public half is repaired at load. */
        err = nvs_set_blob(nvs, NVS_KEY_WG_OLD_PUB, job->old_pub, 32);
        if (err == ESP_OK) err = nvs_set_blob(nvs, NVS_KEY_WG_PRI, job->new_priv, 32);
        if (err == ESP_OK) err = nvs_set_blob(nvs, NVS_KEY_WG_PUB, job->new_pub, 32);
    } else {
        err = nvs_erase_key(nvs, NVS_KEY_WG_OLD_PUB);
        if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    }
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

static void nvs_job_task(void *arg) {
    nvs_job_t *job = (nvs_job_t *)arg;
    job->result = nvs_job_run_now(job);
    xSemaphoreGive(job->done);         /* the waiter owns job and done from here on */
    vTaskDelete(NULL);
}

static esp_err_t nvs_job_run(nvs_job_t *job) {
    job->result = ESP_FAIL;
    job->done = xSemaphoreCreateBinary();
    if (!job->done) return ESP_ERR_NO_MEM;
    if (xTaskCreate(nvs_job_task, "ml_nvs", ML_TASK_WG_MGR_STACK, job,
                    ML_TASK_COORD_PRIO, NULL) != pdPASS) {
        vSemaphoreDelete(job->done);
        job->done = NULL;
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreTake(job->done, portMAX_DELAY);
    vSemaphoreDelete(job->done);
    job->done = NULL;
    return job->result;
}

esp_err_t ml_identity_rotate_node_key(microlink_t *ml, uint8_t new_priv[32], uint8_t new_pub[32]) {
    if (!ml || !new_priv || !new_pub) return ESP_ERR_INVALID_ARG;

    /* A stale OLD_PUB (left by an earlier rotation whose clear failed) is simply
     * overwritten: the key being replaced now is the one that matters. */
    nvs_job_t *job = nvs_job_new(NVS_JOB_ROTATE);
    if (!job) return ESP_ERR_NO_MEM;
    memcpy(job->old_pub, ml->wg_public_key, 32);
    generate_keypair(job->new_priv, job->new_pub);

    esp_err_t err = nvs_job_run(job);
    if (err == ESP_OK) {
        memcpy(new_priv, job->new_priv, 32);
        memcpy(new_pub, job->new_pub, 32);
        memcpy(ml->old_node_pub, job->old_pub, 32);
        ml->old_node_valid = true;
    }
    nvs_job_free(job);
    return err;
}

void ml_identity_clear_old_node_key(microlink_t *ml) {
    if (!ml || !ml->old_node_valid) return;
    nvs_job_t *job = nvs_job_new(NVS_JOB_CLEAR_OLD);
    if (!job) return;                  /* the key stays: harmless, see below */
    if (nvs_job_run(job) == ESP_OK) {
        ml->old_node_valid = false;
        memset(ml->old_node_pub, 0, sizeof(ml->old_node_pub));
    }
    nvs_job_free(job);
    /* On failure the key stays: the next register sends OldNodeKey again, which is harmless. */
}

/* ============================================================================
 * State Queries
 * ========================================================================== */

microlink_state_t microlink_get_state(const microlink_t *ml) {
    return ml ? ml->state : ML_STATE_IDLE;
}

bool microlink_is_connected(const microlink_t *ml) {
    return ml && ml->state == ML_STATE_CONNECTED;
}

uint32_t microlink_get_vpn_ip(const microlink_t *ml) {
    return ml ? ml->vpn_ip : 0;
}

int microlink_get_peer_count(const microlink_t *ml) {
    return ml ? ml->peer_count : 0;
}

esp_err_t microlink_get_peer_info(const microlink_t *ml, int index, microlink_peer_info_t *info) {
    if (!ml || !info || index < 0 || index >= ml->peer_count) {
        return ESP_ERR_INVALID_ARG;
    }
    const ml_peer_t *p = &ml->peers[index];
    info->vpn_ip = p->vpn_ip;
    strncpy(info->hostname, p->hostname, sizeof(info->hostname) - 1);
    memcpy(info->public_key, p->public_key, 32);
    info->online = p->active;
    info->direct_path = p->has_direct_path;
    return ESP_OK;
}

/* ============================================================================
 * Send API
 * ========================================================================== */

esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                          const uint8_t *data, size_t len) {
    if (!ml || !data || len == 0 || len > 1400) return ESP_ERR_INVALID_ARG;
    if (ml->state != ML_STATE_CONNECTED) return ESP_ERR_INVALID_STATE;

    /* Find peer by VPN IP */
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].vpn_ip == dest_vpn_ip && ml->peers[i].active) {
            /* TODO: Route through WireGuard tunnel */
            /* For now, queue via DERP as fallback */
            return ml_derp_queue_send(ml, ml->peers[i].public_key, data, len);
        }
    }
    return ESP_ERR_NOT_FOUND;
}

/* ============================================================================
 * Callbacks
 * ========================================================================== */

void microlink_set_state_callback(microlink_t *ml, microlink_state_cb_t cb, void *user_data) {
    if (ml) { ml->state_cb = cb; ml->state_cb_data = user_data; }
}

void microlink_set_peer_callback(microlink_t *ml, microlink_peer_cb_t cb, void *user_data) {
    if (ml) { ml->peer_cb = cb; ml->peer_cb_data = user_data; }
}

void microlink_set_data_callback(microlink_t *ml, microlink_data_cb_t cb, void *user_data) {
    if (ml) { ml->data_cb = cb; ml->data_cb_data = user_data; }
}

/* ============================================================================
 * Utilities
 * ========================================================================== */

void microlink_ip_to_str(uint32_t ip, char *buf) {
    snprintf(buf, 16, "%lu.%lu.%lu.%lu",
             (unsigned long)((ip >> 24) & 0xFF),
             (unsigned long)((ip >> 16) & 0xFF),
             (unsigned long)((ip >> 8) & 0xFF),
             (unsigned long)(ip & 0xFF));
}

uint32_t microlink_parse_ip(const char *ip_str) {
    if (!ip_str) return 0;
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const char *microlink_default_device_name(void) {
    static char name[48] = {0};
    if (name[0] == 0) {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);

        /* Use ML_DEVICE_NAME as prefix if configured, otherwise "esp32" */
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%02x%02x%02x", prefix, mac[3], mac[4], mac[5]);
    }
    return name;
}

const char *microlink_imei_device_name(void) {
#ifdef CONFIG_ML_ENABLE_CELLULAR
    static char name[48] = {0};  /* prefix + "-" + 15-digit IMEI + null */
    const char *imei = ml_cellular_get_imei();
    if (imei && imei[0]) {
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%s", prefix, imei);
        return name;
    }
#endif
    return NULL;
}

uint64_t ml_get_time_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

/* ============================================================================
 * MagicDNS — Resolve tailnet hostnames against peer list
 * ========================================================================== */

/* Case-insensitive string compare (limited to len bytes) */
static int strncasecmp_local(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

uint32_t microlink_resolve(const microlink_t *ml, const char *hostname) {
    if (!ml || !hostname || hostname[0] == '\0') return 0;

    size_t query_len = strlen(hostname);

    for (int i = 0; i < ml->peer_count; i++) {
        const ml_peer_t *p = &ml->peers[i];
        if (!p->active || p->hostname[0] == '\0') continue;

        /* 1. Exact match (case-insensitive) */
        if (strncasecmp_local(p->hostname, hostname, sizeof(p->hostname)) == 0) {
            return p->vpn_ip;
        }

        /* 2. Prefix match: query "npc1" matches peer "npc1.tail12345.ts.net"
         * The query must match up to the first '.' in the peer hostname. */
        const char *dot = strchr(p->hostname, '.');
        if (dot) {
            size_t short_len = (size_t)(dot - p->hostname);
            if (query_len == short_len &&
                strncasecmp_local(p->hostname, hostname, short_len) == 0) {
                return p->vpn_ip;
            }
        }
    }

    return 0;  /* Not found */
}
