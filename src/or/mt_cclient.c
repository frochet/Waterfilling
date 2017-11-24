
#include "or.h"
#include "config.h"
#include "mt_cclient.h"
#include "mt_common.h"
#include "nodelist.h"
#include "routerlist.h"
#include "util.h"
#include "container.h"
#include "circuitbuild.h"
#include "circuituse.h"
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
  intermediary = intermediary_new(node, ei, now);
  log_info(LD_MT, "Chose an intermediary: %s at time %ld", extend_info_describe(ei),
      (long) now);
  smartlist_add(intermediaries, intermediary);
 err:
  extend_info_free(ei);
  //free intermediary - todo
  //intermediary_free(intermediary);
}

STATIC void
run_cclient_housekeeping_event(time_t now) {
  
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
run_cclient_build_circuit_event(time_t now) {
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
  origin_circuit_t *circ = NULL;
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      intermediary) {
    // XXX MoneTor - make unit test for this function
    circ = circuit_get_by_intermediary_ident(intermediary->identity);
    /* If no circ, launch one */
    if (!circ) {
      int purpose = CIRCUIT_PURPOSE_C_INTERMEDIARY;
      int flags = CIRCLAUNCH_IS_INTERNAL;
      flags |= CIRCLAUNCH_NEED_UPTIME;
      circ = circuit_launch_by_extend_info(purpose, intermediary->ei,
          flags);
      if (!circ) {
        /*intermediary->circuit_retries++;*/
        //problems going to be handled by a function called
        //by cicuit_about_to_free
        continue;
      }
      /*We have circuit building - mark the intermediary*/
      memcpy(circ->inter_ident->identity,
          intermediary->identity->identity, DIGEST_LEN);
    }
    //XXX MoneTor - Check circuit healthiness? - check that it is already
    // done by an other Tor intern function 
  } SMARTLIST_FOREACH_END(intermediary);
}

intermediary_t * mt_cclient_get_intermediary_from_ocirc(origin_circuit_t *ocirc) {
  return NULL;
}

void
run_cclient_scheduled_events(time_t now) {
  /*Make sure our controller is healthy*/
  run_cclient_housekeeping_event(now);
  /*Make sure our intermediaries are up*/
  run_cclient_build_circuit_event(now);
}

void mt_cclient_intermediary_circ_has_closed(origin_circuit_t *circ) {
  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    // means that we did not reach the intermediary point for whatever reason
    // (probably timeout -- retry)
    intermediary_t* intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
    intermediary->circuit_retries++;
  } else {
    /* Circuit has been closed - notify the payment module */

  }
}

/*************************** Object creation and cleanup *******************************/


/**
 * Allocate on the heap a new intermediary and returns the pointer
 */

static intermediary_t *
intermediary_new(const node_t *node, extend_info_t *ei, time_t now) {
  tor_assert(node);
  tor_assert(ei);
  intermediary_t *intermediary = tor_malloc_zero(sizeof(intermediary_t));
  
  memcpy(intermediary->identity, node->identity, DIGEST_LEN);
  strlcpy(intermediary->nickname, node->ri->nickname, sizeof(intermediary->nickname));
  intermediary->is_reachable = INTERMEDIARY_REACHABLE_MAYBE;
  intermediary->chosen_at = now;
  intermediary->ei = ei;
  return intermediary;
}

static void
intermediary_free(intermediary_t *intermediary) {
  if (!intermediary)
    return;
  extend_info_free(intermediary->ei);
  if (intermediary->m_channel) {
    // XXX MoneTor implem following function
    //mt_desc_free(intermediary->m_channel);
  }
  tor_free(intermediary);
}

