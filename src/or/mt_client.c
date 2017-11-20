#include "mt_client.h"

//TODO:
//    rethink global variables
//    figure out which data structures we need to send info
//    modifiy handlers to accept tokens instead of messages
//    have all functions return list of cells + connection to send it to

//TODO: rethink end user / intermediary tokens
int mt_client_init(mt_client* client, byte (*pk)[SIZE_PK], byte (*sk)[SIZE_SIZE], chn_end_data* chns[], int num_chns){

    // record key and addrs
    if(pk != NULL && sk != NULL){
	memcpy(client.pk, *pk, SIZE_PK);
	memcpy(client.sk, *sk, SIZE_SK);
	pk_to_addr(pk, &client.addr);
    }

    // add provided channels to list
    client.channels = g_array_new();
    for(int i = 0; i < num_chns; i++){
	chn_end_data* chn = malloc(sizeof(chn_end_data));
	memcpy(chn, chns[i], sizeof(chn_end_data));
	g_array_append_val(client.channels, chn);
    }

    // establish circuit to ledger

    // if we have not already connected with entry
    //    if we are out of open microchannels then create one
    //    send first cell of micro_establish with entry
    //    send first cell of nano_establish with entry
}

int mt_client_establish(mt_client* client, circuit_t* circ){

    // if we do not have enough open channels
    //    send first cell of chn_init with the ledger
    //    send first cell of chn_establish with an intermediary

    // pop off available channel with lowest funds remaining
    // send first cell of nan_establish with remaining circuits
}

int mt_client_pay(mt_client* client, circuit_t* circ){
    // loop through all relays in circuit
    //    send nan_pay cell
}

int mt_client_close(mt_client* client, circuit_t* circ){
    // loop through middle and entry
    //     send first cell of nan_close with each
}

int mt_client_cashout(mt_client* client, byte (*chn_addrs)[SIZE_ADDR]){
    // send first cell of cashout protocol with ledger
    // optional: connect to intermediary/entry and warn them
}

int mt_client_handle(mt_client* client, edge_connection_t* conn){

    ntype type; //= extract from cell
    int result;

    // process cells and compile into full on messages here if the message is complete
    byte* msg;

    switch(type){
	case NTYPE_CHN_INT_ESTAB2:
	    result = chn_int_estab2(msg, circ, conn, layer);
	    break;
	case NTYPE_CHN_INT_ESTAB4:
	    result = chn_int_estab4(msg, circ, conn, layer);
	    break;
	case NTYPE_MIC_CLI_PAY1:
	    result = mic_cli_pay1(msg, circ, conn, layer);
	    break;
	case NTYPE_MIC_REL_PAY2:
	    result = mic_rel_pay2(msg, circ, conn, layer);
	    break;
	case NTYPE_MIC_INT_PAY4:
	    result = mic_int_pay4(msg, circ, conn, layer);
	    break;
	case NTYPE_MIC_INT_PAY7:
	    result = mic_int_pay7(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_SETUP2:
	    result = nan_int_setup2(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_SETUP4:
	    result = nan_int_setup4(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_SETUP6:
	    result = nan_int_setup6(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE2:
	    result = nan_int_close2(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE4:
	    result = nan_int_close4(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE6:
	    result = nan_int_close6(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE8:
	    result = nan_int_close8(msg, circ, conn, layer);
	    break;
	case NTYPE_MAC_LED_DATA:
	    result = mac_led_data(msg, circ, conn, layer);
	    break;
	case NTYPE_CHN_LED_DATA:
	    result = chn_led_data(msg, circ, conn, layer);
	    break;
	default:
	    result = MT_ERROR;
    }

    return result;
}

int handle_chn_int_estab2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_chn_int_estab4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mic_cli_pay1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mic_rel_pay2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mic_int_pay4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mic_int_pay7(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_setup2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_setup4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_setup6(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_close2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_close4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_close6(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_close8(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mac_led_data(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_chn_led_data(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
