#include "or.h"
#include "mt_cintermediary.h"
#include "mt_common.h"
#include "container.h"

/**
 */

static digestmap_t *desc2circ = NULL;



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
}
