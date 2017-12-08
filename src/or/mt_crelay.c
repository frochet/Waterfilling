
#include "or.h"
#include "mt_crelay.h"

void
mt_crelay_intermediary_circ_has_closed(origin_circuit_t* ocirc) {
  (void) ocirc;
}

void 
mt_crelay_intermediary_circ_has_opened(origin_circuit_t* ocirc) {
  (void) ocirc;
}

int
mt_crelay_send_message(mt_desc_t* desc, mt_ntype_t type,
    byte* msg, int size) {
  
  (void)desc;
  (void)type;
  (void)msg;
  (void)size;
  return 0;
}
