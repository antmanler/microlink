/**
 * @file ml_login.c
 * @brief Interactive-login data shared between the coord task and the app
 *
 * The login URL and the node's own MagicDNS name are written by the coord task
 * and read by the application through microlink_copy_*(). The copies are made
 * under id_lock so a reader never sees a half-written string, and a getter
 * never truncates: it fails when the caller's buffer is too small.
 *
 * Nothing here logs: the URL is a login capability.
 *
 * Kept apart from microlink.c (NVS, tasks, WiFi) so the host harness
 * (tools/host-register-probe) compiles and tests this exact code.
 */

#include "microlink_internal.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Login URL and self name (coord task writes, app reads under id_lock)
 * ========================================================================== */

void ml_set_auth_url(microlink_t *ml, const char *url_or_null) {
    char *copy = NULL;
    if (url_or_null && url_or_null[0]) {
        size_t n = strlen(url_or_null);
        copy = malloc(n + 1);
        if (!copy) return;
        memcpy(copy, url_or_null, n + 1);
    }
    portENTER_CRITICAL(&ml->id_lock);
    char *old = ml->auth_url;
    ml->auth_url = copy;
    portEXIT_CRITICAL(&ml->id_lock);
    if (old) {
        volatile uint8_t *v = (volatile uint8_t *)old;
        for (size_t i = strlen(old); i > 0; i--) v[i - 1] = 0;   /* the URL is a login capability */
        free(old);
    }
}

void ml_set_self_fqdn(microlink_t *ml, const char *fqdn) {
    if (!fqdn) return;
    size_t n = strlen(fqdn);
    while (n > 0 && fqdn[n - 1] == '.') n--;       /* Node.Name ends with a dot */
    if (n == 0 || n > ML_DNS_NAME_MAX) return;     /* invalid: keep the previous name */
    char tmp[ML_DNS_NAME_MAX + 1];
    memcpy(tmp, fqdn, n);
    tmp[n] = '\0';
    portENTER_CRITICAL(&ml->id_lock);
    memcpy(ml->self_fqdn, tmp, n + 1);
    portEXIT_CRITICAL(&ml->id_lock);
}

/* Copy src (len bytes + NUL) into buf, or fail without touching buf. */
static esp_err_t copy_out(char *buf, size_t buf_len, const char *src, size_t src_len) {
    if (buf_len < src_len + 1) return ESP_ERR_INVALID_SIZE;
    memcpy(buf, src, src_len);
    buf[src_len] = '\0';
    return ESP_OK;
}

esp_err_t microlink_copy_auth_url(const microlink_t *ml, char *buf, size_t len) {
    if (!ml || !buf || len == 0) return ESP_ERR_INVALID_ARG;
    portMUX_TYPE *lock = (portMUX_TYPE *)&ml->id_lock;
    esp_err_t ret = ESP_ERR_NOT_FOUND;
    portENTER_CRITICAL(lock);
    if (ml->auth_url) ret = copy_out(buf, len, ml->auth_url, strlen(ml->auth_url));
    portEXIT_CRITICAL(lock);
    return ret;
}

size_t microlink_get_auth_url_length(const microlink_t *ml) {
    if (!ml) return 0;
    portMUX_TYPE *lock = (portMUX_TYPE *)&ml->id_lock;
    size_t n = 0;
    portENTER_CRITICAL(lock);
    if (ml->auth_url) n = strlen(ml->auth_url);
    portEXIT_CRITICAL(lock);
    return n;
}

const char *ml_device_name(const microlink_t *ml) {
    return (ml->config.device_name && ml->config.device_name[0])
               ? ml->config.device_name : microlink_default_device_name();
}

esp_err_t microlink_copy_device_name(const microlink_t *ml, char *buf, size_t len) {
    if (!ml || !buf || len == 0) return ESP_ERR_INVALID_ARG;
    const char *name = ml_device_name(ml);
    return copy_out(buf, len, name, strlen(name));
}

esp_err_t microlink_copy_self_fqdn(const microlink_t *ml, char *buf, size_t len) {
    if (!ml || !buf || len == 0) return ESP_ERR_INVALID_ARG;
    portMUX_TYPE *lock = (portMUX_TYPE *)&ml->id_lock;
    esp_err_t ret = ESP_ERR_NOT_FOUND;
    portENTER_CRITICAL(lock);
    if (ml->self_fqdn[0]) ret = copy_out(buf, len, ml->self_fqdn, strlen(ml->self_fqdn));
    portEXIT_CRITICAL(lock);
    return ret;
}

/* Same rule as the SDK's MagicDNSSuffixOfNodeName: everything after the first
 * label, or the whole name when it has no dot. */
esp_err_t microlink_copy_magicdns_suffix(const microlink_t *ml, char *buf, size_t len) {
    if (!ml || !buf || len == 0) return ESP_ERR_INVALID_ARG;
    portMUX_TYPE *lock = (portMUX_TYPE *)&ml->id_lock;
    esp_err_t ret = ESP_ERR_NOT_FOUND;
    portENTER_CRITICAL(lock);
    if (ml->self_fqdn[0]) {
        const char *dot = strchr(ml->self_fqdn, '.');
        const char *suffix = (dot && dot[1]) ? dot + 1 : ml->self_fqdn;
        ret = copy_out(buf, len, suffix, strlen(suffix));
    }
    portEXIT_CRITICAL(lock);
    return ret;
}

microlink_error_t microlink_get_error(const microlink_t *ml) {
    return ml ? ml->last_error : ML_ERR_NONE;
}
