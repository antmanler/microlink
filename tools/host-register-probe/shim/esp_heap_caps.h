#pragma once
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#define MALLOC_CAP_SPIRAM   (1u << 10)
#define MALLOC_CAP_8BIT     (1u << 2)
#define MALLOC_CAP_INTERNAL (1u << 11)
static inline void *heap_caps_malloc(size_t size, uint32_t caps) { (void)caps; return malloc(size); }
static inline void *heap_caps_calloc(size_t n, size_t size, uint32_t caps) { (void)caps; return calloc(n, size); }
