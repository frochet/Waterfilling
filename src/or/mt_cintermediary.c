#include "or.h"
#include "mt_cintermediary.h"
#include "mt_common.h"
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

static digestmap_t *desc2circ = NULL;

static smartlist_t *ledgercircs = NULL;
static smartlist_t *ledgers = NULL;
static int count = 1;

/********************** Once per second events ***********************/

STATIC void
run_cintermediary_housekeeping_event(time_t now) {
  (void) now;
  /** Create ledger_t */
}

STATIC void
run_cintermediary_build_circuit_event(time_t now) {
  /* if Tor is not up, we stop  */
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit())
    return;
  /* We get our ledger circuit and we built one if it is NULL */
  
  /* How many of them do we build? - should be linked to 
   * our consensus weight */
  origin_circuit_t *circ = NULL;
  
  ledger_t *ledger = mt_cintermediary_get_ledger();

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
}

/********************** Utility stuff ********************************/

ledger_t *mt_cintermediary_get_ledger(void) {
  return NULL;
}

/********************** Payment related functions ********************/

int
mt_cintermediary_send_message(mt_desc_t *desc, mt_ntype_t pcommand,
    byte *msg, int size) {
  (void) desc;
  (void) pcommand;
  (void) msg;
  (void) size;
  return 0;
}

void
mt_cintermediary_process_received_msg(circuit_t *circ, mt_ntype_t pcommand,
    byte *msg, size_t msg_len) {
  (void) circ;
  (void) pcommand;
  (void) msg;
  (void) msg_len;
}


/*************************** init and free functions *****************/

void mt_cintermediary_init(void) {
  desc2circ = digestmap_new();
  ledgercircs = smartlist_new();
  ledgers = smartlist_new();
}
