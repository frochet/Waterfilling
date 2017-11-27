
#include "or.h"
#include "config.h"
#include "mt_cclient.h"
#include "mt_common.h"
#include "nodelist.h"
#include "routerlist.h"
#include "util.h"
#include "container.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "torlog.h"
#include "router.h"
#include "main.h"


/* Some forward static declaration for ease of implem */

static intermediary_t* intermediary_new(const node_t *node, extend_info_t *ei, time_t now);

STATIC void run_cclient_housekeeping_event(time_t now);

static void choose_intermediaries(time_t now, smartlist_t *exclude_list);

static void intermediary_need_cleanup(intermediary_t *intermediary,
    time_t now);

STATIC void run_cclient_build_circuit_event(time_t now);

static void intermediary_free(intermediary_t *intermediary);

/*List of selected intermediaries */
static smartlist_t *intermediaries = NULL;

smartlist_t *get_intermediaries(int for_circuit) {
  (void)for_circuit;
  return NULL;
}

void
mt_cclient_init(void) {
  tor_assert(!intermediaries); //should never be called twice
  intermediaries = smartlist_new();
}

/**
 * Remove the intermdiary from the list we are using because
 * of one of the following reasons::
 * XXX MoneTor - FR: do we implement all of them?
 * - Node does not exist anymore in the consensus (do we care for simulation?)
 * - The intermediary maximum circuit retry count has been reached (we DO care about that)
 * - The intermediary has expired (we need to cashout and rotate => do we care?)
 */
static void
intermediary_need_cleanup(intermediary_t *intermediary, time_t now) {
  (void) now;
  if (intermerdiary->circuit_retries > INTERMEDIARY_MAX_RETRIES) {
    /* Remove intermediary from the list */
    SMARTLIST_FOREACH_BEGIN(INTERMEDIARY_MAX_RETRIES, intermediary_t *,
        inter) {
      if (tor_memeq(intermediary->identity->identity, 
            inter->identity->identity, DIGEST_LEN)){
        SMARTLIST_DEL_CURRENT(intermediaries, inter);
        intermediary_free(intermediary);
        log_info(LD_MT, "Removing intermediary from list %ld",
            (long) now);
      }
    } SMARTLIST_FOREACH_END(inter);
  }
}
  

/*
 * Fill the intermediaries smartlist_t with selected
 * intermediary_t
 *
 * XXX MoneTor - parse the state file to recover previously
 *               intermediaries
 * 
 * If no intermediaries in the statefile, select new ones
 */
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
  intermediary_free(intermediary);
}

/* Scheduled event run from the main loop every second.
 * Make sure our controller is healthy, including
 * intermediaries status, payment status, etc
 */
STATIC void
run_cclient_housekeeping_event(time_t now) {
  
  /* Check intermediary health*/
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      intermediary) {
    if (intermediary->is_reachable == INTERMEDIARY_REACHABLE_NO) {
      /* intermediary is not reachable for a reason, checks 
       * what's happening, log some information and rotate
       * the intermediary */
      intermediary_need_cleanup(intermediary, now);
    }
  } SMARTLIST_FOREACH_END(intermediary);
}

/*
 * Scheduled event run from the main loop every second.
 * Makes sure we always have circuits build towards
 * the intermediaries
 */
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

intermediary_t* mt_cclient_get_intermediary_from_ocirc(origin_circuit_t *ocirc) {
  intermediary_identity_t *inter_ident = ocirc->inter_ident;
  intermediary_t *intermediary = NULL;
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *, intermediary_tmp) {
    if (tor_memeq(inter_ident->identity, intermediary_tmp->identity->identity,
          DIGEST_LEN)) {
      intermediary = intermediary_tmp;
      break;
    }
  } SMARTLIST_FOREACH_END(intermediary_tmp);
  /* This should be considered as a bug ?*/
  if (BUG(!intermediary))
    return NULL;
  return intermediary;
}

void
run_cclient_scheduled_events(time_t now) {
  /*Make sure our controller is healthy*/
  run_cclient_housekeeping_event(now);
  /*Make sure our intermediaries are up*/
  run_cclient_build_circuit_event(now);
}

/**
 * We got notified that a CIRCUIT_PURPOSE_C_INTERMEDIARY has closed
 *  - Is this a remote close?
 *  - Is this a local close due to a timeout error or a circuit failure?
 */
void mt_cclient_intermediary_circ_has_closed(origin_circuit_t *circ) {
  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    // means that we did not reach the intermediary point for whatever reason
    // (probably timeout -- retry)
    intermediary_t* intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
    intermediary->circuit_retries++;
    /* Do we need to cleanup our intermediary? */
    time_t now = approx_time();
    intermediary_need_cleanup(intermediary, now);
  } else {
    /* Circuit has been closed - notify the payment module */

  }
}

/**
 * We got notified that a CIRCUIT_PURPOSE_C_INTERMEDIARY has opened
 */
void mt_cclient_intermediary_circ_has_opened(origin_circuit_t *circ) {
  (void)circ;
  /* reset circuit_retries counter */

  /*XXX MoneTor - What do we do? notify payment, wait to full establishement of all circuits?*/
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
  if (intermediary->ei)
    extend_info_free(intermediary->ei);
  if (intermediary->m_channel) {
    // XXX MoneTor implem following function
    //mt_desc_free(intermediary->m_channel);
  }
  tor_free(intermediary);
}

