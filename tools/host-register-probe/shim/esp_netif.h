/* Host shim: no interfaces. add_endpoints_to_json() then lists no LAN endpoint. */
#pragma once
#include <stdint.h>
typedef struct esp_netif_obj esp_netif_t;
typedef struct { struct { uint32_t addr; } ip; } esp_netif_ip_info_t;
static inline esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key) { (void)key; return 0; }
static inline int esp_netif_get_ip_info(esp_netif_t *n, esp_netif_ip_info_t *i) { (void)n; (void)i; return -1; }
