/**
 * @file ml_peer_updates.c
 * @brief Peer updates from the coord task to the wg_mgr task
 *
 * The coord task appends one update per netmap peer before wg_mgr starts to
 * drain (wg_mgr waits for ML_EVT_COORD_REGISTERED, which coord sets after the
 * first netmap). The count is the tailnet's peer count, so no fixed depth
 * fits: a full queue drops updates, and a send that blocks deadlocks, since
 * coord would wait for wg_mgr while wg_mgr waits for coord.
 *
 * Updates are PSRAM allocations already, so a FIFO list linked through
 * ml_peer_update_t.next costs nothing per item. peer_updates_lock covers
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

/* Appends at the tail. Never blocks, never drops. */
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

void ml_peer_updates_deinit(microlink_t *ml) {
    ml_peer_update_t *update = ml_peer_updates_take_all(ml);
    while (update) {
        ml_peer_update_t *next = update->next;
        free(update);
        update = next;
    }
}
