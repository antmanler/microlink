/* Host shim: FreeRTOS types and inert stand-ins. The harness drives the coord
 * functions directly, so no task, queue or event group is ever created. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

typedef void *TaskHandle_t;
typedef void *QueueHandle_t;
typedef void *EventGroupHandle_t;
typedef void *SemaphoreHandle_t;
typedef uint32_t EventBits_t;
typedef uint32_t TickType_t;
typedef uint32_t StackType_t;
typedef int BaseType_t;
typedef struct { int unused; } portMUX_TYPE;

#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY 0xFFFFFFFFu
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
#define portMUX_INITIALIZE(m) ((void)(m))
#define portENTER_CRITICAL(m) ((void)(m))
#define portEXIT_CRITICAL(m) ((void)(m))

#define BIT0 (1u << 0)
#define BIT1 (1u << 1)
#define BIT2 (1u << 2)
#define BIT3 (1u << 3)
#define BIT4 (1u << 4)
#define BIT5 (1u << 5)
#define BIT6 (1u << 6)
#define BIT7 (1u << 7)
#define BIT8 (1u << 8)
#define BIT9 (1u << 9)
#define BIT10 (1u << 10)
#define BIT11 (1u << 11)
#define BIT12 (1u << 12)
#define BIT13 (1u << 13)

static inline void vTaskDelay(TickType_t ms) { usleep(ms * 1000u); }
static inline void vTaskDelete(TaskHandle_t t) { (void)t; }
static inline void vTaskSuspend(TaskHandle_t t) { (void)t; }
static inline int xPortGetCoreID(void) { return 0; }
/* Bits set on any event group are recorded for the tests; reads return
 * shim_event_bits_get, which a test sets (host_stubs.c). */
extern EventBits_t shim_event_bits_set;
extern EventBits_t shim_event_bits_get;
static inline EventBits_t xEventGroupGetBits(EventGroupHandle_t e) { (void)e; return shim_event_bits_get; }
static inline EventBits_t xEventGroupSetBits(EventGroupHandle_t e, EventBits_t b) {
    (void)e; shim_event_bits_set |= b; return b;
}
static inline EventBits_t xEventGroupClearBits(EventGroupHandle_t e, EventBits_t b) {
    (void)e; EventBits_t prev = shim_event_bits_get; shim_event_bits_get &= ~b; return prev;
}
static inline EventBits_t xEventGroupWaitBits(EventGroupHandle_t e, EventBits_t b, BaseType_t c,
                                              BaseType_t a, TickType_t t) {
    (void)e; (void)b; (void)c; (void)a; (void)t; return 0;
}
/* Receives come from a test-filled queue (host_stubs.c); others are empty. */
BaseType_t shim_queue_receive(QueueHandle_t q, void *item);
static inline BaseType_t xQueueReceive(QueueHandle_t q, void *item, TickType_t t) {
    (void)t; return shim_queue_receive(q, item);
}
/* The harness records what is sent to the coord command queue (host_stubs.c). */
BaseType_t shim_queue_send(QueueHandle_t q, const void *item);
static inline BaseType_t xQueueSend(QueueHandle_t q, const void *item, TickType_t t) {
    (void)t; return shim_queue_send(q, item);
}
