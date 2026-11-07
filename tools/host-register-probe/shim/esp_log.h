/* Host shim: ESP_LOGx goes through probe_log(), silent unless PROBE_LOG is set.
 * MicroLink logs states and sizes only; PROBE_LOG still never sees a login URL. */
#pragma once
#include <stdarg.h>
void probe_log(char level, const char *tag, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
#define ESP_LOGE(tag, fmt, ...) probe_log('E', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) probe_log('W', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) probe_log('I', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) probe_log('D', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGV(tag, fmt, ...) probe_log('V', tag, fmt, ##__VA_ARGS__)
