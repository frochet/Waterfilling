#include "or.h"
#include "mt_cintermediary.h"
#include "mt_common.h"
#include "mt_ipay.h"
#include "container.h"
#include "circuitbuild.h"
#include "circuituse.h"
#include "circuitlist.h"
#include "router.h"
#include "relay.h"
#include "torlog.h"
#include "nodelist.h"
#include "util.h"
#include "main.h"

STATIC void run_cintermediary_housekeeping_event(time_t now);
STATIC void run_cintermediary_build_circuit_event(time_t now);
static void ledger_free(void);
static void ledger_init(const node_t *node, extend_info_t *ei, time_t now);

static digestmap_t *desc2circ = NULL;

static smartlist_t *ledgercircs = NULL;
static ledger_t* ledger = NULL;
static int count = 1;

/********************** Once per second events ***********************/

STATIC void
run_cintermediary_housekeeping_event(time_t now) {
  (void) now;
}

/**
 * Once we have enough consensus information we try to build circuit
 * towards the ledger and maintain them open
 */

STATIC void
run_cintermediary_build_circuit_event(time_t now) {
  /* if Tor is not up, we stop  */
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit())
    return;
  /* We get our ledger circuit and we built one if it is NULL */
  extend_info_t *ei = NULL;
  if (!ledger) {
    const node_t* node;
    node = node_find_ledger();
    if (!node) {
      log_info(LD_MT, "Hey, we do not have a ledger in our consensus?");
      return;  /** For whatever reason our consensus does not have a ledger */
    }
    ei = extend_info_from_node(node, 0);
    if (!ei) {
      log_info(LD_MT, "extend_info_from_node failed?");
      goto err;
    }
    ledger_init(node, ei, now);
  }


  /* How many of them do we build? - should be linked to 
   * our consensus weight */
  origin_circuit_t *circ = NULL;
  
  while (smartlist_len(ledgercircs) < NBR_LEDGER_CIRCUITS &&
         ledger->circuit_retries < NBR_LEDGER_CIRCUITS*LEDGER_MAX_RETRIES) {
    /* this is just about load balancing */
    log_info(LD_MT, "We do not have enough ledger circuits - launching one more");
    int purpose = CIRCUIT_PURPOSE_I_LEDGER;
    int flags = CIRCLAUNCH_IS_INTERNAL;
    flags |= CIRCLAUNCH_NEED_UPTIME;
    circ = circuit_launch_by_extend_info(purpose, ledger->ei,
        flags);
    if (!circ) {
      ledger->circuit_retries++;
    }
    else {
      smartlist_add(ledgercircs, circ);
    }
  }
  return;
 err:
  extend_info_free(ei);
  ledger_free();
  return;
}

/********************** circ event ***********************************/

void mt_cintermediary_ledgercirc_has_opened(circuit_t *circ) {
  (void) circ;
}

void mt_cintermediary_ledgercirc_has_closed(circuit_t *circ) {
  time_t now;
  /* If the circuit is closed before we successfully extend
   * a general circuit towards the ledger, then we may have
   * a reachability problem.. */
  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    log_info(lD_MT, "MoneTor: Looks like we did not extend a circuit successfully"
        " towards the ledger");
  }
}

void mt_cintermediary_orcirc_has_closed(or_circuit_t *circ) {
  buf_free(circ->buf);
  mt_desc_free(&circ->desc);
  // TODO remove this circuit from our structures
}

/** We've received the first payment cell over that circuit 
 * init structure as well as add this circ in our structures*/

void mt_cintermediary_init_desc_and_add(or_circuit_t *circ) {
  circ->desc.id = count++; // XXX change that later to a 128bit rand 
  /*Cell received has been sent either by a relay or by a client
   *Todo => check with Thien-Nam what desc.party we have to configure */
  circ->desc.party = MT_PARTY_INT; 
}


/********************** Utility stuff ********************************/

ledger_t *mt_cintermediary_get_ledger(void) {
  return ledger;
}

/********************** Payment related functions ********************/

int
mt_cintermediary_send_message(mt_desc_t *desc, mt_ntype_t pcommand,
    byte *msg, int size) {
  (void) desc;
  (void) pcommand;
  (void) msg;
  (void) size;
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  /** Might happen if the circuit has been closed */
  // We can go a bit further and re-send the command for 
  // ledger circuits when it is up again.
  // XXX TODO
  if (!circ || circ->marked_for_close || circ->state !=
      CIRCUIT_STATE_OPEN) {
    return -1;
  }
  return relay_send_pcommand_from_edge(circ, RELAY_COMMAND_MT,
      pcommand, (const char*) msg, size);
}

void
mt_cintermediary_process_received_msg(circuit_t *circ, mt_ntype_t pcommand,
    byte *msg, size_t msg_len) {
  mt_desc_t *desc;
  or_circuit_t *orcirc;
  if (circ->purpose == CIRCUIT_PURPOSE_I_LEDGER) {
    tor_assert(ledger);
    desc = &ledger->desc;
    if (mt_ipay_recv(desc, pcommand, msg, msg_len) < 0) {
      log_info(LD_MT, "Payment module returned -1 for mt_ntype_t %hhx", pcommand);
      // XXX decides what to do
    }
  }
  else if (circ->purpose == CIRCUIT_PURPOSE_INTERMEDIARY) {
    orcirc = TO_OR_CIRCUIT(circ);
    desc = &orcirc->desc;
    if (mt_ipay_recv(desc, pcommand, msg, msg_len) < 0) {
      log_info(LD_MT, "Payment module returned -1 for mt_ntype_t %hhx", pcommand);
      //decides what to do
    }
  }
  else {
    log_info(LD_MT, "Processing circuit with unsupported purpose %hhx",
        circ->purpose);
  }
}


/*************************** init and free functions *****************/

void mt_cintermediary_init(void) {
  desc2circ = digestmap_new();
  ledgercircs = smartlist_new();
}

/*
 * Initialize our static ledger
 */

static void
ledger_init(const node_t *node, extend_info_t *ei, time_t now) {
  tor_assert(node);
  tor_assert(ei);
  ledger = tor_malloc_zero(sizeof(ledger_t));
  memcpy(ledger->identity.identity, node->identity, DIGEST_LEN);
  ledger->is_reachable = LEDGER_REACHABLE_MAYBE;
  ledger->desc.id = count++; // XXX change this counter to 128-bit digest
  ledger->desc.party = MT_PARTY_LED;
  ledger->ei = ei;
  ledger->buf = buf_new_with_capacity(RELAY_PPAYLOAD_SIZE);
  log_info(LD_MT, "Ledger created at %lld", (long long) now);
}

static void ledger_free(void) {
  if (!ledger)
    return;
  if (ledger->ei)
    extend_info_free(ledger->ei);
  buf_free(ledger->buf);
  tor_free(ledger);
}
