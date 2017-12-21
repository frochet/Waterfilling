#ifndef mt_cintermediary_h
#define mt_cintermediary_h

#include "or.h"

void mt_cintermediary_init(void);


/********************* Ledger struct *****************************/

#define LEDGER_REACHABLE_NO 0
#define LEDGER_REACHABLE_YES 1
#define LEDGER_REACHABLE_MAYBE 2
#define LEDGER_MAX_RETRIES 3

#define NBR_LEDGER_CIRCUITS 1

typedef struct ledger_identity_t {
  char identity[DIGEST_LEN];
} ledger_identity_t;

typedef struct ledger_t {
  ledger_identity_t identity;
  
  unsigned int is_reachable:2;
  extend_info_t *ei;
  
  mt_desc_t desc;
  
  struct buf_t *buf;
  
  uint32_t circuit_retries;
} ledger_t;

void run_cintermediary_scheduled_events(time_t now);


/********************* Circ event ********************************/

void mt_cintermediary_ledgercirc_has_opened(circuit_t *circ);

void mt_cintermediary_ledgercirc_has_closed(circuit_t *circ);

/** When a CIRCUIT_PURPOSE_INTERMEDIARY closes, this function
 * should be called */

void mt_cintermediary_orcirc_has_closed(or_circuit_t *circ);

/** We've received the fist cell over what is now a CIRCUIT_PURPOSE_INTERMEDIARY
 * we initiate the new mt_desc_t and we add this circuit into our 
 * structures */
void  mt_cintermediary_init_desc_and_add(or_circuit_t *circ);

/********************* Utility stuffs ****************************/

ledger_t *mt_cintermediary_get_ledger(void);

/********************* Payment related messages ******************/

int mt_cintermediary_send_message(mt_desc_t* desc,
    mt_ntype_t type, byte *msg, int size);

void mt_cintermediary_process_received_msg(circuit_t *circ,
    mt_ntype_t pcommand, byte *msg, size_t msg_len);

#endif
