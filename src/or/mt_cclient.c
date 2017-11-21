
#include "or.h"
#include "mt_cclient.h"
#include "mt_common.h"


/*List of selected intermediaries */
static smartlist_t *intermediaries = NULL;

void
mt_cclient_init() {
  tor_assert(!intermediaries); //should never be called twice
  intermediaries = smartlist_new();
}

static void
run_housekeeping_event(time_t now) {
  (void) now;
}

static void
run_build_circuit_event(time_t now) {
  /*If Tor is not fully up (can takes 30 sec), we do not consider
   * building circuits*/
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit())
    return;

  /*For each intermediary in our list, verifies that we have a circuit
   *up and running. If not, build one.*/

  SMARTLIST_FOREACH_BEGIN(intermediaries, const intermerdiary_t *,
      intermediary) {
    //XXX MoneTor todo - define intermediary_t
  } SMARTLIST_FOREACH_END(intermediary);
}

void
run_cclient_scheduled_events(time_t now) {
  /*Make sure our controller is healthy*/
  run_housekeeping_event(now);
  /*Make sure our intermediaries are up*/
  run_build_circuit_event(now);
}
