
#include "or.h"
#include "config.h"
#include "mt_cclient.h"
#include "mt_common.h"
#include "nodelist.h"
#include "routerlist.h"
#include "util.h"
#include "container.h"
#include "circuitbuild.h"
#include "torlog.h"
#include "router.h"
#include "main.h"

/*List of selected intermediaries */
static smartlist_t *intermediaries = NULL;


smartlist_t *get_intermediaries(int for_circuit) {
  return NULL;
}

void
mt_cclient_init() {
  tor_assert(!intermediaries); //should never be called twice
  intermediaries = smartlist_new();
}

static void
cleanup_intermediary(intermediary_t *intermediary, time_t now) {
  (void) intermediary;
  (void) now;
}

/**
 * Allocate on the heap a new intermediary and returns the pointer
 */

static intermediary_t *
intermediary_new(const node_t *node, extend_info_t *ei) {
  intermediary_t *intermediary = tor_malloc_zero(sizeof(intermediary_t));

  // XXX MoneTor todo
  return intermediary;
}

static void
choose_intermediaries(time_t now, smartlist_t *exclude_list) {
  if (smartlist_len(intermediaries) == MAX_INTERMEDIARY_CHOSEN)
    return;
  /*We do not have enough node, let's pick some.*/
  const node_t *node;
  /*Handling extend info here is going to ease my life - great idea of the day*/
  extend_info_t *ei = NULL;
  intermediary_t *intermediary = NULL;

  /*Normal intermediary flags - We just need uptime*/
  router_crn_flags_t flags = CRN_NEED_UPTIME;

  node = router_choose_random_node(exclude_list, get_options()->ExcludeNodes,
      flags);

  if (!node) {
    goto err;
  }
  /* Since we have to provide extend_info for clients to connect as a 4th relay from a 3-hop
   * path, let's extract it now? */
  ei = extend_info_from_node(node, 0);

  if (!ei) {
    goto err;
  }
  /* Create the intermediary object */
  intermediary = intermediary_new(node, ei);
  log_info(LD_MT, "Chose an intermediary: %s", extend_info_describe(ei));
  smartlist_add(intermediaries, intermediary);
 err:
  extend_info_free(ei);
  //free intermediary - todo
  //intermediary_free(intermediary);
}

STATIC void
run_housekeeping_event(time_t now) {
  
  /* Check intermediary health*/
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      intermediary) {
    if (intermediary->is_reachable == INTERMEDIARY_REACHABLE_NO) {
      /* intermediary is not reachable for a reason, checks 
       * what's happening, log some information and rotate
       * the intermediary */
      cleanup_intermediary(intermediary, now);
    }
  } SMARTLIST_FOREACH_END(intermediary);
}

STATIC void
run_build_circuit_event(time_t now) {
  /*If Tor is not fully up (can takes 30 sec), we do not consider
   *building circuits*/
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit())
    return;

  /*Do we have enough intermediaries? if not, select new ones */
  /*exclude list is the intermediary list. Do we have any reason to extend this list
    to other relays?*/
  choose_intermediaries(now, intermediaries);

  /*For each intermediary in our list, verifies that we have a circuit
   *up and running. If not, build one.*/

  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
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
