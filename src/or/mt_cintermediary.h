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


/********************* Utility stuffs ****************************/

ledger_t *mt_cintermediary_get_ledger(void);

/********************* Payment related messages ******************/

int mt_cintermediary_send_message(mt_desc_t* desc,
    mt_ntype_t type, byte *msg, int size);

void mt_cintermediary_process_received_msg(circuit_t *circ,
    mt_ntype_t pcommand, byte *msg, size_t msg_len);

#endif
