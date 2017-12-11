#ifndef mt_crelay_h


void mt_crelay_intermediary_circ_has_closed(origin_circuit_t* ocirc);

void mt_crelay_intermediary_circ_has_opened(origin_circuit_t* ocirc);


int mt_crelay_send_message(mt_desc_t* desc, uint8_t command, mt_ntype_t type,
    byte* msg, int size);
#define mt_crelay_h
#endif
