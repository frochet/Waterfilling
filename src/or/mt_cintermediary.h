#ifndef mt_cintermediary_h
#define mt_cintermediary_h


void mt_cintermediary_init(void);


/********************* Payment related messages ******************/

int mt_cintermediary_send_message(mt_desc_t* desc,
    mt_ntype_t type, byte *msg, int size);

void mt_cintermediary_process_received_msg(circuit_t *circ,
    mt_ntype_t pcommand, byte *msg, size_t msg_len);

#endif
