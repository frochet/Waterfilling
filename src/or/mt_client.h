#ifndef mt_client_h
#define mt_client_h

#include "mt.h"
#include "mt_crypto.h"
#include "mt_tokens.h"

#define TARGET_NUM_CHANNELS

typedef struct {
    mt_pay_cb* pay;
    mt_send_cb* send;

    pk[SIZE_PK];
    sk[SIZE_SK];
    addr[SIZE_ADDR];

    chn_end_data* guard_chn;
    GArray* channels;

    circuit_t* led_circ;
} mt_client

// Tor-facing API
int mt_client_init(mt_client* client, byte (*pk)[SIZE_PK], byte (*sk)[SIZE_SIZE],
		   chn_end_data* chn_data, int num_chns, mt_pay_cb* pay, mt_send_cb* send);
int mt_client_establish(mt_client* client, circuit_t* circ);
int mt_client_pay(mt_client* client, circuit_t* circ);
int mt_client_close(mt_client* client, circuit_t* circ);
int mt_client_cashout(mt_client* client, byte (*chn_addrs)[SIZE_ADDR]);
int mt_client_handle(mt_client* client, cell_t* cell, mt_ctx* ctx);

// private handler functions
int handle_chn_int_estab2(mt_client* client, chn_int_estab2* token, mt_ctx* ctx);
int handle_chn_int_estab4(mt_client* client, chn_int_estab4* token, mt_ctx* ctx);
int handle_mic_cli_pay1(mt_client* client, mic_cli_pay1* token, mt_ctx* ctx);
int handle_mic_rel_pay2(mt_client* client, mic_rel_pay2* token, mt_ctx* ctx);
int handle_mic_int_pay4(mt_client* client, mic_int_pay4* token, mt_ctx* ctx);
int handle_mic_int_pay7(mt_client* client, mic_int_pay7* token, mt_ctx* ctx);
int handle_nan_int_setup2(mt_client* client, nan_int_setup2* token, mt_ctx* ctx);
int handle_nan_int_setup4(mt_client* client, nan_int_setup4* token, mt_ctx* ctx);
int handle_nan_int_setup6(mt_client* client, nan_int_setup6* token, mt_ctx* ctx);
int handle_nan_int_close2(mt_client* client, nan_int_close2* token, mt_ctx* ctx);
int handle_nan_int_close4(mt_client* client, nan_int_close4* token, mt_ctx* ctx);
int handle_nan_int_close6(mt_client* client, nan_int_close6* token, mt_ctx* ctx);
int handle_nan_int_close8(mt_client* client, nan_int_close8* token, mt_ctx* ctx);
int handle_mac_led_data(mt_client* client, mac_led_data* token, mt_ctx* ctx);
int handle_chn_led_data(mt_client* client, chn_led_data* token, mt_ctx* ctx);

//handle intermediaries
//XXX MoneTor maybe all of intermediary-handling
//    function need to be in a separate file?

smartlist_t* get_intermediaries(int for_circuit);
/**
 * Picks a random intermediary from our pre-built list
 * of available intermediaries
 */
const node_t* choose_random_intermediary(void);
/**
 * XXX MoneTor edge_connection_t* should have some information
 * about the payment channel that is used with that intermediary
 * or does not if this is a fresh payment channel
 */
extend_info_t* mt_client_get_intermediary_from_edge(edge_connection_t* conn);


/** 
 * Parse the state file to get the intermediaries we were using before
 * 
 * NOT URGENT
 */
int intermediary_parse_state(or_state_t *state, int set, char** msg);
#endif
