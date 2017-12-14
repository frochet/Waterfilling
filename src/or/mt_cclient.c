
#include "or.h"
#include "config.h"
#include "mt_cclient.h"
#include "mt_common.h"
#include "mt_cpay.h"
#include "mt_ipay.h"
#include "channel.h"
#include "nodelist.h"
#include "routerlist.h"
#include "util.h"
#include "container.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "relay.h"
#include "router.h"
#include "torlog.h"
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
/*Contains which origin_circuit_t is related to desc
 *a get operation will need to be done at each payment callback call
 *- Is there enough performance?? */
static digestmap_t* desc2circ = NULL; // mt_desc2digest => origin_circuit_t
/*static counter of descriptors - also used as id*/

static uint32_t desc_id = 0;

/*
 * Builds and returns a smartlist_t containing node_t objects
 * of intermediaries
 */
smartlist_t* get_node_t_smartlist_intermerdiaries(void) {
  smartlist_t *all_inter_nodes = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t*, intermediary) {
    smartlist_add(all_inter_nodes, (void *)node_get_by_id(intermediary->identity->identity));
  }SMARTLIST_FOREACH_END(intermediary);
  return all_inter_nodes;
}

/*
 * Get the first intermediary withing the list intermediaries that
 * matches linked_to to position
 */
intermediary_t* get_intermediary_by_role(position_t position) {
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t*, intermediary) {
    if (intermediary->linked_to == position)
      return intermediary;
  } SMARTLIST_FOREACH_END(intermediary);
  return NULL;
}

smartlist_t* get_intermediaries(int for_circuit) {
  (void)for_circuit;
  return NULL;
}

void
mt_cclient_init(void) {
  log_info(LD_MT, "MoneTor: initialization of controler client code");
  tor_assert(!intermediaries); //should never be called twice
  intermediaries = smartlist_new();
  desc2circ = digestmap_new();
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
  if (intermediary->circuit_retries > INTERMEDIARY_MAX_RETRIES ||
      intermediary->is_reachable == INTERMEDIARY_REACHABLE_NO) {

    /* Get all general circuit linked to this intermediary and
     * mark the payment as closed */
    // XXX MoneTor todo

    /* Remove intermediary from the list */
    SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
        inter) {
      if (tor_memeq(intermediary->identity->identity,
            inter->identity->identity, DIGEST_LEN)){
        byte id[DIGEST_LEN];
        mt_desc2digest(&intermediary->desc, &id);
        digestmap_remove(desc2circ, (char*) id);
        SMARTLIST_DEL_CURRENT(intermediaries, inter);
        intermediary_free(intermediary);
        log_info(LD_MT, "MoneTor: Removing intermediary from list %ld",
            (long) now);
      }
    } SMARTLIST_FOREACH_END(inter);
  }
}

/*
 * This function is responsible to choose the right intermediary
 * to use with the circuit circ, create the descriptor
 * mt_desc_t * and notify the payment module that we
 * want to establish a payment circuit.
 */

void
mt_cclient_launch_payment(origin_circuit_t* circ) {
  log_info(LD_MT, "MoneTor - Initiating payment - calling payment module");
  circ->ppath->desc.id = desc_id++;
  circ->ppath->desc.party = MT_PARTY_REL;
  /* Choosing right intermediary */
  tor_assert(circ->ppath->next);
  pay_path_t* middle = circ->ppath->next;
  intermediary_t* intermediary_g = get_intermediary_by_role(MIDDLE);
  middle->desc.id = desc_id++;
  middle->desc.party = MT_PARTY_REL;
  /* Log if intermediary is NULL? Should not happen*/
  tor_assert_nonfatal(intermediary_g);
  
  if (intermediary_g) {
    memcpy(middle->inter_ident->identity, intermediary_g->identity->identity,
        DIGEST_LEN);
  }
  tor_assert(middle->next);
  pay_path_t* exit = middle->next;
  intermediary_t* intermediary_e = get_intermediary_by_role(EXIT);
  exit->desc.id = desc_id++;
  exit->desc.party = MT_PARTY_REL;
  tor_assert_nonfatal(intermediary_e);
  
  if (intermediary_e) {
    memcpy(exit->inter_ident->identity, intermediary_e->identity->identity,
        DIGEST_LEN);
  }
  log_info(LD_MT, "MoneTor - Adding circ's descs %s to digestmap",
      mt_desc_describe(&circ->ppath->desc));
  /* Adding new elements to digestmap */
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->ppath->desc, &id);
  digestmap_set(desc2circ, (char*) id, circ);
  log_info(LD_MT, "MoneTor - Adding circ's descs %s to digestmap",
      mt_desc_describe(&middle->desc));
  mt_desc2digest(&middle->desc, &id);
  digestmap_set(desc2circ, (char*) id, circ);
  log_info(LD_MT, "MoneTor - Adding circ's descs %s to digestmap",
      mt_desc_describe(&exit->desc));
  mt_desc2digest(&exit->desc, &id);
  digestmap_set(desc2circ, (char*) id, circ);
  // XXX MoneTor - what to do with retVal
  /*Now, notify payment module that we have to start a payment*/
  int retVal;
  log_info(LD_MT, "MoneTor - Calling payment module for direct payment"
      " with param %s and %s", mt_desc_describe(&circ->ppath->desc),
      mt_desc_describe(&circ->ppath->desc));
  /* Direct payment to the guard */
  retVal = mt_cpay_pay(&circ->ppath->desc, &circ->ppath->desc);
  if (retVal < 0) {
    //XXX MoneTor - Do we mark the payment for close?
    circ->ppath->p_marked_for_close = 1;
    // If first one marked for close, do we close the others?
  }
  log_info(LD_MT, "MoneTor - Calling payment module for direct payment"
      " with param %s and %s", mt_desc_describe(&middle->desc),
      mt_desc_describe(&intermediary_g->desc));
  /* Payment to the middle relay involving intermediary */
  retVal = mt_cpay_pay(&middle->desc, &intermediary_g->desc);
  if (retVal < 0) {
    middle->p_marked_for_close = 1;
  }
  log_info(LD_MT, "MoneTor - Calling payment module for direct payment"
      " with param %s and %s", mt_desc_describe(&exit->desc),
      mt_desc_describe(&intermediary_e->desc));
  /* Payment to the exit relay involving intermediary */
  retVal = mt_cpay_pay(&exit->desc, &intermediary_e->desc);
  if (retVal < 0) {
    exit->p_marked_for_close = 1;
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
  log_info(LD_MT, "MoneTor: Choosing intermediaries");
  /*We do not have enough node, let's pick some.*/
  const node_t *node;
  /*Handling extend info here is going to ease my life - great idea of the day*/
  extend_info_t *ei = NULL;
  intermediary_t *intermediary = NULL;
  int count_middle = 0, count_exit = 0;
  /*Normal intermediary flags - We just need uptime*/
  router_crn_flags_t flags = CRN_NEED_UPTIME;
  flags |= CRN_NEED_INTERMEDIARY;

  node = router_choose_random_node(exclude_list, get_options()->ExcludeNodes,
      flags);
  
  if (!node) {
    log_warn(LD_MT, "MoneTor - Something went wrong, we did not select any intermediary");
    goto err;
  }
  log_info(LD_MT, "MoneTor: Chosen relay %s as intermediary", node_describe(node));
  
  /* Since we have to provide extend_info for clients to connect as a 4th relay from a 3-hop
   * path, let's extract it now? */
  ei = extend_info_from_node(node, 0);

  if (!ei) {
    goto err;
  }
  /* Check how much we have for each position and give this
   * new intermediary the position value matching the smaller
   * value */
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      inter) {
    if (inter->linked_to == MIDDLE)
      count_middle++;
    if (inter->linked_to == EXIT)
      count_exit++;
  } SMARTLIST_FOREACH_END(inter);
  /* Create the intermediary object */
  log_info(LD_MT, "MoneTor: Chose an intermediary: %s at time %ld", extend_info_describe(ei),
      (long) now);
  intermediary = intermediary_new(node, ei, now);
  if (count_middle < count_exit)
    intermediary->linked_to = MIDDLE;
  else
    intermediary->linked_to = EXIT;
  //tor_assert(count_middle+counter_exit <= MAX_INTERMEDIARY_CHOSEN);
  smartlist_add(intermediaries, intermediary);
  log_info(LD_MT, "MoneTor: added intermediary to list");
  return;
 err:
  extend_info_free(ei);
  intermediary_free(intermediary);
  return;
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
      log_info(LD_MT, "MoneTor: Intermediary marked as not reachable"
          " calling cleanup now %ld", (long) now);
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
  smartlist_t *excludesmartlist = get_node_t_smartlist_intermerdiaries();
  choose_intermediaries(now, excludesmartlist);
  smartlist_free(excludesmartlist);

  /*For each intermediary in our list, verifies that we have a circuit
   *up and running. If not, build one.*/
  origin_circuit_t *circ = NULL;
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      intermediary) {
    // XXX MoneTor - make unit test for this function
    circ = circuit_get_by_intermediary_ident(intermediary->identity);
    /* If no circ, launch one */
    if (!circ) {
      log_info(LD_MT, "No circ towards intermediary %s",
          extend_info_describe(intermediary->ei));
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
      log_info(LD_MT, "MoneTor: Building intermediary circuit towards %s", 
          node_describe(node_get_by_id(intermediary->identity->identity)));
      circ->inter_ident = tor_malloc_zero(sizeof(intermediary_identity_t));
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
  /* If we're a authority or a relay,
   * we don't enable payment */
  if (authdir_mode(get_options()) ||
      server_mode(get_options()))
    return;
  /*Make sure our controller is healthy*/
  run_cclient_housekeeping_event(now);
  /*Make sure our intermediaries are up*/
  run_cclient_build_circuit_event(now);
}

/**
 * XXX MoneTor -- TODO here: general_circuit_has_closed()
 */

void mt_cclient_general_circ_has_closed(origin_circuit_t *circ) {
  if (circ->ppath) {
    log_info(LD_MT, "a general circuit has closed");
    // verify what to do.. ? notify payment module?
  }
}


/**
 * We got notified that a CIRCUIT_PURPOSE_C_INTERMEDIARY has closed
 *  - Is this a remote close?
 *  - Is this a local close due to a timeout error or a circuit failure?
 */
void mt_cclient_intermediary_circ_has_closed(origin_circuit_t *circ) {
  intermediary_t* intermediary = NULL;
  intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
  time_t now;
  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    // means that we did not reach the intermediary point for whatever reason
    // (probably timeout -- retry)
    intermediary->circuit_retries++;
    if (intermediary->is_reachable == INTERMEDIARY_REACHABLE_YES)
      intermediary->is_reachable = INTERMEDIARY_REACHABLE_MAYBE;
    else if (intermediary->is_reachable == INTERMEDIARY_REACHABLE_MAYBE &&
        intermediary->circuit_retries > INTERMEDIARY_MAX_RETRIES) {
      intermediary->is_reachable = INTERMEDIARY_REACHABLE_NO;
      goto cleanup;
    }

    /* maybe because extrainfo is not fresh anymore?  XXX change that :s*/
    node_t* node = node_get_mutable_by_id(intermediary->identity->identity);
    extend_info_t *ei = extend_info_from_node(node, 0);
    if (!ei) {
      intermediary->is_reachable = INTERMEDIARY_REACHABLE_NO;
      goto cleanup;
    }
    extend_info_free(intermediary->ei);
    intermediary->ei = ei;
  } else {
    /* Remove desc ->circ from digestmap */
    byte id[DIGEST_LEN];
    mt_desc2digest(&intermediary->desc, &id);
    digestmap_remove(desc2circ, (char*) id);
    /* Circuit has been closed - notify the payment module */
  }

 cleanup:
  /* Do we need to cleanup our intermediary? */
  if (intermediary) {
    now = approx_time();
    intermediary_need_cleanup(intermediary, now);
  }
}

/**
 * We got notified that a CIRCUIT_PURPOSE_C_INTERMEDIARY has opened
 */
void 
mt_cclient_intermediary_circ_has_opened(origin_circuit_t *circ) {
  (void)circ;
  log_info(LD_MT, "MoneTor: Yay! intermediary circuit opened");
  /* reset circuit_retries counter */
  //Todo
  /* add intermediary desc and circ in digestmap */
  intermediary_t* intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
  byte id[DIGEST_LEN];
  mt_desc2digest(&intermediary->desc, &id);
  digestmap_set(desc2circ, (char*) id, circ);

  /*XXX MoneTor - What do we do? notify payment, wait to full establishement of all circuits?*/
}

/**
 * Sending messages to intermediaries, relays and ledgers
 */

int
mt_cclient_send_message(mt_desc_t* desc, uint8_t command, mt_ntype_t type,
    byte* msg, int size) {
  /* init and stuff */
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  origin_circuit_t* circ = digestmap_get(desc2circ, (char*) id);
  tor_assert(circ);
  if (command == RELAY_COMMAND_MT) {
    /*defensive prog from payment module*/
    /*tor_assert(size <= RELAY_PPAYLOAD_SIZE);*/
    // XXX Sending many cells depending of size
    return relay_send_pcommand_from_edge(TO_CIRCUIT(circ), command, (uint8_t) type,
        (const char*) msg, size);
  }
  else if (command == CELL_PAYMENT) {
    tor_assert(size <= CELL_PAYLOAD_SIZE-RELAY_PHEADER_SIZE);
    // XXX MoneTor todo
    cell_t cell;
    relay_pheader_t rph;
    memset(&cell, 0, sizeof(cell_t));
    memset(&rph, 0, sizeof(relay_pheader_t));
    cell.circ_id = TO_CIRCUIT(circ)->n_circ_id;
    cell.command = command;
    rph.pcommand = type;
    rph.length = size-1;
    direct_pheader_pack(cell.payload, &rph);
    memcpy(cell.payload+RELAY_PHEADER_SIZE, msg+1, rph.length);
    log_info(LD_MT, "Adding cell payment %d to queue", rph.pcommand);
    cell_queue_append_packed_copy(NULL, &TO_CIRCUIT(circ)->n_chan_cells, 0, &cell,
        TO_CIRCUIT(circ)->n_chan->wide_circ_ids, 0);
    /* We flush if we have no cells in this queue */
    if (!channel_has_queued_writes(TO_CIRCUIT(circ)->n_chan)) {
      log_info(LD_MT, "Flushing payment cell");
      // XXX CHECK THAT IT IS THE RIGHT WAY
      channel_flush_from_first_active_circuit(TO_CIRCUIT(circ)->n_chan, 1);
    }
    return 0;
  }
  else {
    log_warn(LD_MT, "Unrecognized command %d", command);
  }
  return -1;
}

/** Process received micro, nano payment cells from either relay, intermediary
 * or ledger - Call the payment module and decides what
 * to do upon failure
 */
void
mt_cclient_process_received_relaycell(origin_circuit_t *circ, relay_header_t *rh,
    relay_pheader_t *rph, crypt_path_t *layer_hint, const uint8_t *payload) {
  (void) rh; //no need - refactor code?
  mt_desc_t *desc;
  /*What type of node sent us this cell? relay, intermediary or ledger? */
  if (TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_INTERMEDIARY) {
    intermediary_t *intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
    desc = &intermediary->desc;
    byte *msg = tor_malloc(rph->length);
    memcpy(msg, payload, rph->length);
    log_info(LD_MT, "Processed a cell sent by our intermediary %s - calling mt_ipay_recv",
        extend_info_describe(intermediary->ei));
    // XXX Buffering cells?
    if (mt_cpay_recv(desc, rph->pcommand, msg, rph->length) < 0) {
      // XXX Do we mark this circuit for close and complain about
      // intermediary?
      // XXX Do we notify all general circuit that the payment will not complete?

    }
    tor_free(msg);
  }
  else if (TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_GENERAL) {

    pay_path_t *ppath = circ->ppath;
    crypt_path_t *cpath = circ->cpath;
    tor_assert(ppath);
    tor_assert(cpath);

    /* find the right ppath */
    do {
      cpath = cpath->next;
      ppath = ppath->next;
    } while (cpath != layer_hint);
    /* get the right desc */
    desc = &ppath->desc;
    byte *msg = tor_malloc(rph->length);
    memcpy(msg, payload, rph->length);
    //XXX todo Buffering cells
    log_info(LD_MT, "Processed a cell sent by relay linked to desc %s - calling mt_cpay_recv",
        mt_desc_describe(desc));
    if (mt_cpay_recv(desc, rph->pcommand, msg, rph->length) < 0) {
      /* De we retry or close? Let's assume easiest things -> we close*/
      ppath->p_marked_for_close = 1;
    }
    tor_free(msg);
  }
  else {
    log_warn(LD_MT, "intermediary circuit not implemented yet");
  }
}

/** Process a direct payment cell sent by our guard
 */
void
mt_cclient_process_received_directpaymentcell(origin_circuit_t *circ, cell_t *cell, 
    relay_pheader_t *rph) {
  tor_assert(circ->ppath);
  mt_desc_t *desc = &circ->ppath->desc;
  if (mt_cpay_recv(desc, rph->pcommand, cell->payload+RELAY_PHEADER_SIZE,
        rph->length) < 0) {
    // XXX MoneTor what to do if we fail here?
  }
}

/*************************** Object creation and cleanup *******************************/


static void
pay_path_free(pay_path_t* ppath) {
  if (!ppath)
    return;
  tor_free(ppath->inter_ident);
  /* Recursive call to explore the linked list */
  pay_path_free(ppath->next);
}

/*
 * XXX MoneTor - Todo: call them in appropriate place
 */
void 
mt_cclient_general_circuit_free(origin_circuit_t* circ) {
  if (!circ)
    return;
  pay_path_free(circ->ppath);
}

void 
mt_cclient_intermediary_circuit_free(origin_circuit_t* circ) {
  if (!circ)
    return;
  tor_free(circ->inter_ident);
}

/**
 * Allocate on the heap a new intermediary and returns the pointer
 */

static intermediary_t *
intermediary_new(const node_t *node, extend_info_t *ei, time_t now) {
  tor_assert(node);
  tor_assert(ei);
  intermediary_t *intermediary = tor_malloc_zero(sizeof(intermediary_t));
  intermediary->identity = tor_malloc_zero(sizeof(intermediary_t));
  memcpy(intermediary->identity->identity, node->identity, DIGEST_LEN);
  //XXX MoneTor change nickname to something else, or remove nickname
  //intermediary->nickname = tor_strdup(node->ri->nickname);
  intermediary->is_reachable = INTERMEDIARY_REACHABLE_MAYBE;
  intermediary->desc.id = desc_id++;
  intermediary->desc.party = MT_PARTY_INT;
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
  tor_free(intermediary);
}
