
#include "or.h"
#include "container.h"
#include "config.h"
#include "mt_common.h"
#include "mt_crelay.h"
#include "mt_rpay.h"
#include "router.h"

static uint64_t count[2] = {0, 0}; 
static digestmap_t  *desc2circ = NULL;
static ledger_t *ledger = NULL;
static smartlist_t *ledgercircs = NULL;

static void run_crelay_housekeeping_event(time_t now);
static void run_crelay_build_circuit_event(time_t now);

void
mt_crelay_init(void) {
  log_info(LD_MT, "MoneTor: initialization of controler relay code");
  ledgercircs = smartlist_new();
  desc2circ = digestmap_new();
  count[0] = rand_uint64();
  count[1] = rand_uint64();
}

void mt_crelay_init_desc_and_add(or_circuit_t *circ) {
  circ->desc.id[0] = count[0];
  circ->desc.id[1] = count[1];
  circ->desc.party = MT_PARTY_CLI; // Which party shoud I put?
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  digestmap_set(desc2circ, (char*) id, circ);
}

ledger_t *
mt_crelay_get_ledger(void) {
  return ledger;
}

/************************** Open and close events **************/
void
mt_crelay_intermediary_circ_has_closed(origin_circuit_t* ocirc) {
  (void) ocirc;
}

void 
mt_crelay_intermediary_circ_has_opened(origin_circuit_t* ocirc) {
  (void) ocirc;
}

/************************** Events *****************************/

static void
run_crelay_housekeeping_event(time_t now) {
  (void) now;
}

/**
 *  Ensure that ledgers circuits are up 
 *  Ensure that current circuit toward intermediaries
 *  are up ~ if not, rebuilt circuit to them. Eventually
 *  tell the payment controller that we cannot connect
 *  to the intermediary to cashout and stop prioritizing
 *  the circuit(s) related to this intermediary 
 *  
 *  Recall: Intermediary circuits are built when
 *  we receive information by a client
 *  */

static void
run_crelay_build_circuit_event(time_t now) {
  (void) now;
}

void
run_crelay_scheduled_events(time_t now) {
  if (intermediary_mode(get_options()) ||
      authdir_mode(get_options()))
    return;
  /* Make sure our controller is healthy */
  run_crelay_housekeeping_event(now);
  /* Make sure our ledger circuit and curent intermediary
   * circuits are up */
  run_crelay_build_circuit_event(now);
}

/************************** Payment related functions ********************/

int
mt_crelay_send_message(mt_desc_t* desc, uint8_t command, mt_ntype_t type,
    byte* msg, int size) {
  (void)desc;
  (void)command;
  (void)type;
  (void)msg;
  (void)size;
  return 0;
}

void
mt_crelay_process_received_msg(circuit_t *circ, mt_ntype_t pcommand,
    byte *msg, size_t msg_len) {
  mt_desc_t *desc;
  or_circuit_t *orcirc;
  if (CIRCUIT_IS_ORIGIN(circ)) {
  // should be a ledger circuit or a circuit to an interemdiary
  }
  else {
    //circ should a or_circuit_t of a normal circuit with
    //a normal client over one endpoint
    orcirc = TO_OR_CIRCUIT(circ);
    desc = &orcirc->desc;
    if (mt_rpay_recv(desc, pcommand, msg, msg_len) < 0) {
      log_info(LD_MT, "MoneTor: Payment module returnerd -1"
          " we should stop prioritizing this circuit");
      orcirc->mt_priority = 0;
    }
  }
}
