#include "mt_relay.h"

// Tor-facing API
int mt_relay_init(byte (*pk)[SIZE_PK], byte (*sk)[SIZE_SIZE], chn_end_data*  chns[], int num_chns){

    //record key and addrs
    if(pk != NULL && sk != NULL){
	memcpy(mt_relay.pk, *pk, SIZE_PK);
	memcpy(mt_relay.sk, *sk, SIZE_SK);
	pk_to_addr(pk, &cli_addr);
    }

    // add provided channels to list
    mt_relay.channels = g_array_new();
    for(int i = 0; i < num_chns; i++){
	chn_end_data* chn = malloc(sizeof(chn_end_data));
	memcpy(chn, chns[i], sizeof(chn_end_data));
	g_array_append_val(mt_relay.channels, chn);
    }

    // establish circuit to ledger
}

int mt_relay_cashout(byte (*chn_addrs)[SIZE_PK]){
    // send first cell of cashout protocol with ledger
    // optional: connect to intermediary/entry and warn them
}

int mt_relay_handle(cell_t *cell, circid_t* circ, edge_connection_t* conn, crypt_path_t *layer){

    ntype type; //= extract from cell
    int result;

    // process cells and compile into full on messages here if the message is complete
    byte* msg;

    switch(type){

	case NTYPE_CHN_INT_ESTAB2:
	    result = handle_chn_int_estab2(msg, circ, conn, layer);
	    break;
	case NTYPE_CHN_INT_ESTAB4:
	    result = handle_chn_int_estab4(msg, circ, conn, layer);
	    break;
	case NTYPE_MIC_CLI_PAY1:
	    result = handle_mic_cli_pay1(msg, circ, conn, layer);
	    break;
	case NTYPE_MIC_CLI_PAY5:
	    result = handle_mic_cli_pay5(msg, circ, conn, layer);
	    break;
	case NTYPE_MIC_INT_PAY8:
	    result = handle_mic_int_pay8(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_CLI_ESTAB1:
	    result = handle_nan_cli_estab1(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_ESTAB3:
	    result = handle_nan_int_estab3(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_ESTAB5:
	    result = handle_nan_int_estab5(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_CLI_PAY1:
	    result = handle_nan_cli_pay1(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE2:
	    result = handle_nan_int_close2(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE4:
	    result = handle_nan_int_close4(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE6:
	    result = handle_nan_int_close6(msg, circ, conn, layer);
	    break;
	case NTYPE_NAN_INT_CLOSE8:
	    result = handle_nan_int_close8(msg, circ, conn, layer);
	    break;
	case NTYPE_MAC_LED_DATA:
	    result = handle_mac_led_data(msg, circ, conn, layer);
	    break;
	case NTYPE_CHN_LED_DATA:
	    result = handle_chn_led_data(msg, circ, conn, layer);
	    break;
	default:
	    result = MT_ERROR;
    }

    return result;
}

int handle_chn_int_estab2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_chn_int_estab4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_mic_cli_pay1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_mic_cli_pay5(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_mic_int_pay8(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_cli_estab1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_int_estab3(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_int_estab5(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_cli_pay1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_int_close2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_int_close4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_int_close6(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_nan_int_close8(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_mac_led_data(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
int handle_chn_led_data(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t *layer){}
