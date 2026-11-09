/**
 * @file ml_peer_updates.c
 * @brief Peer updates from the coord task to the wg_mgr task
 *
 * The coord task appends one update per netmap peer, and wg_mgr takes nothing
 * until coord sets ML_EVT_COORD_REGISTERED, so a whole netmap waits here first.
 * The count is the tailnet's peer count, so no fixed depth fits: a full queue
 * drops updates, and a send that blocks deadlocks, since coord would wait for
 * wg_mgr while wg_mgr waits for coord.
 *
 * Without that bit (a login waiting for approval) every reconnect reads the
 * full netmap again. Coord flushes the older updates first (do_fetch_peers),
 * and the end of a session flushes too (microlink_stop), so before
 * registration the list holds one netmap plus the deltas after it.
 *
 * Updates come from ml_psram_calloc: PSRAM, with internal RAM as the fallback.
 * A list linked through ml_peer_update_t.next adds one pointer (4 bytes on the
 * target) to each update and allocates nothing more. peer_updates_lock covers
 * only pointer operations: producers append, the consumer detaches the whole
 * list and walks it outside the lock. A critical section is the lock
 * microlink uses for such short cross-task state (see id_lock).
 */

#include "microlink_internal.h"
#include <stdlib.h>

void ml_peer_updates_init(microlink_t *ml) {
    portMUX_INITIALIZE(&ml->peer_updates_lock);
    ml->peer_updates_head = NULL;
    ml->peer_updates_tail = NULL;
}

/* Appends at the tail and wakes wg_mgr. Never blocks, never drops. */
void ml_peer_updates_push(microlink_t *ml, ml_peer_update_t *update) {
    update->next = NULL;
    portENTER_CRITICAL(&ml->peer_updates_lock);
    if (ml->peer_updates_tail) {
        ml->peer_updates_tail->next = update;
    } else {
        ml->peer_updates_head = update;
    }
    ml->peer_updates_tail = update;
    portEXIT_CRITICAL(&ml->peer_updates_lock);
    ml_wg_mgr_wake(ml);
}

/* Detaches everything pending. The caller owns the returned list. */
ml_peer_update_t *ml_peer_updates_take_all(microlink_t *ml) {
    portENTER_CRITICAL(&ml->peer_updates_lock);
    ml_peer_update_t *head = ml->peer_updates_head;
    ml->peer_updates_head = NULL;
    ml->peer_updates_tail = NULL;
    portEXIT_CRITICAL(&ml->peer_updates_lock);
    return head;
}

/* Frees what the consumer never took. Used when the session ends: the next one
 * starts with a full netmap, so these updates are stale. */
void ml_peer_updates_flush(microlink_t *ml) {
    ml_peer_update_t *update = ml_peer_updates_take_all(ml);
    while (update) {
        ml_peer_update_t *next = update->next;
        free(update);
        update = next;
    }
}
