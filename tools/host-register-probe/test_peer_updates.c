/**
 * Tests of the coord -> wg_mgr peer-update list (ml_peer_updates.c), run on the host.
 *
 * ml_peer_updates.c is #included so two of its dependencies can be swapped:
 *   - free() counts what is released, so a leak shows on every platform (and the
 *     Makefile also builds this test with AddressSanitizer);
 *   - the critical section becomes a real mutex, so the threaded test is a true
 *     producer/consumer race, and a free() under the lock is caught.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "microlink_internal.h"

static int g_failed, g_total;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_total++;                                                           \
        if (!(cond)) {                                                       \
            g_failed++;                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int t_lock_depth;
#undef portENTER_CRITICAL
#undef portEXIT_CRITICAL
#define portENTER_CRITICAL(m) (pthread_mutex_lock(&g_mutex), t_lock_depth++)
#define portEXIT_CRITICAL(m)  (t_lock_depth--, pthread_mutex_unlock(&g_mutex))

static long g_live;             /* updates allocated by this test and not yet freed */
static int g_free_under_lock;   /* free() calls made while the list lock was held */
static void counting_free(void *p) {
    if (p) {
        __atomic_fetch_sub(&g_live, 1, __ATOMIC_RELAXED);
        if (t_lock_depth != 0) g_free_under_lock++;
    }
    free(p);
}
#define free counting_free
#include "ml_peer_updates.c"
#undef free

/* The sequence number rides in vpn_ip. */
static ml_peer_update_t *new_update(uint32_t seq) {
    ml_peer_update_t *u = calloc(1, sizeof(*u));
    u->action = ML_PEER_ADD;
    u->vpn_ip = seq;
    __atomic_fetch_add(&g_live, 1, __ATOMIC_RELAXED);
    return u;
}

/* What wg_mgr does with a detached list: walk it in order, free each. Returns the
 * count; *next_seq advances while the sequence is unbroken, *ordered tells if it was. */
static long consume(ml_peer_update_t *list, uint32_t *next_seq, bool *ordered) {
    long n = 0;
    while (list) {
        ml_peer_update_t *next = list->next;
        if (list->vpn_ip != *next_seq) *ordered = false;
        *next_seq = list->vpn_ip + 1;
        counting_free(list);
        list = next;
        n++;
    }
    return n;
}

static microlink_t *new_ml(void) {
    microlink_t *ml = calloc(1, sizeof(*ml));
    ml_peer_updates_init(ml);
    return ml;
}

/* A first netmap queues one update per tailnet peer before anything drains. Every one
 * of them arrives, in order; none is dropped at the old depths (32 and 400) or beyond. */
static void test_burst_before_any_consumer(void) {
    enum { BURST = 500 };
    microlink_t *ml = new_ml();
    CHECK(ml_peer_updates_take_all(ml) == NULL);            /* empty list */
    for (uint32_t i = 0; i < BURST; i++) ml_peer_updates_push(ml, new_update(i));
    CHECK(g_live == BURST);

    uint32_t next = 0;
    bool ordered = true;
    CHECK(consume(ml_peer_updates_take_all(ml), &next, &ordered) == BURST);
    CHECK(ordered && next == BURST);
    CHECK(g_live == 0);
    CHECK(ml_peer_updates_take_all(ml) == NULL);            /* detached whole */
    free(ml);
}

/* Destroy with updates wg_mgr never took: all are freed, and the list stays usable. */
static void test_deinit_frees_pending(void) {
    microlink_t *ml = new_ml();
    ml_peer_updates_deinit(ml);                             /* nothing pending: harmless */
    CHECK(g_live == 0);

    for (uint32_t i = 0; i < 200; i++) ml_peer_updates_push(ml, new_update(i));
    CHECK(g_live == 200);
    ml_peer_updates_deinit(ml);
    CHECK(g_live == 0);
    CHECK(ml->peer_updates_head == NULL && ml->peer_updates_tail == NULL);
    CHECK(g_free_under_lock == 0);

    ml_peer_updates_deinit(ml);                             /* twice: harmless */
    uint32_t next = 7;
    bool ordered = true;
    ml_peer_updates_push(ml, new_update(next));
    CHECK(consume(ml_peer_updates_take_all(ml), &next, &ordered) == 1 && ordered);
    CHECK(g_live == 0);
    free(ml);
}

/* Producing and consuming in turns keeps FIFO order, and a push after a take starts a
 * fresh list: it is never linked behind the list that was already detached. */
static void test_interleaved_fifo(void) {
    microlink_t *ml = new_ml();
    uint32_t produced = 0, consumed = 0;
    bool ordered = true;
    long taken = 0;
    uint32_t lcg = 12345;
    for (int round = 0; round < 1000; round++) {
        lcg = lcg * 1103515245u + 12345u;
        int pushes = (int)((lcg >> 16) % 9);                /* 0 to 8 per round */
        for (int i = 0; i < pushes; i++) ml_peer_updates_push(ml, new_update(produced++));
        if ((lcg >> 8) % 3 == 0) {
            taken += consume(ml_peer_updates_take_all(ml), &consumed, &ordered);
        }
    }
    taken += consume(ml_peer_updates_take_all(ml), &consumed, &ordered);
    CHECK(ordered && taken == (long)produced && consumed == produced);
    CHECK(g_live == 0);

    /* The tail of a detached list does not point into the next one. */
    ml_peer_updates_push(ml, new_update(0));
    ml_peer_updates_push(ml, new_update(1));
    ml_peer_update_t *first = ml_peer_updates_take_all(ml);
    ml_peer_updates_push(ml, new_update(2));
    CHECK(first && first->vpn_ip == 0 && first->next && first->next->vpn_ip == 1 &&
          first->next->next == NULL);
    ml_peer_update_t *second = ml_peer_updates_take_all(ml);
    CHECK(second && second->vpn_ip == 2 && second->next == NULL);
    counting_free(first->next);
    counting_free(first);
    counting_free(second);
    CHECK(g_live == 0);
    free(ml);
}

/* A producer thread and a consumer thread race on one list: no update is lost or
 * reordered, and nothing is freed under the lock. */
enum { THREADED_ITEMS = 100000 };
static int g_producer_done;

static void *producer(void *arg) {
    microlink_t *ml = arg;
    for (uint32_t i = 0; i < THREADED_ITEMS; i++) ml_peer_updates_push(ml, new_update(i));
    __atomic_store_n(&g_producer_done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void test_threaded_fifo(void) {
    microlink_t *ml = new_ml();
    pthread_t th;
    pthread_create(&th, NULL, producer, ml);
    uint32_t next = 0;
    bool ordered = true;
    long taken = 0;
    bool done;
    do {
        done = __atomic_load_n(&g_producer_done, __ATOMIC_ACQUIRE);
        taken += consume(ml_peer_updates_take_all(ml), &next, &ordered);
    } while (!done);                  /* one more take after the last push */
    pthread_join(th, NULL);
    CHECK(ordered && taken == THREADED_ITEMS && next == THREADED_ITEMS);
    CHECK(ml_peer_updates_take_all(ml) == NULL);
    CHECK(g_live == 0 && g_free_under_lock == 0);
    free(ml);
}

int main(void) {
    test_burst_before_any_consumer();
    test_deinit_frees_pending();
    test_interleaved_fifo();
    test_threaded_fifo();
    printf("%d peer-update checks, %d failed\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
