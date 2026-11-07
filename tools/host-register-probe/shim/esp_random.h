#pragma once
#include <stdlib.h>
#include <stddef.h>
static inline void esp_fill_random(void *buf, size_t len) { arc4random_buf(buf, len); }
