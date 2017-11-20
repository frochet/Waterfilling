#include "mt_intermediary.h"

int mt_intermediary_init(byte (*pk)[SIZE_PK], byte (*sk)[SIZE_SIZE], chn_end_data*  chns[], int num_chns){

  // record key and addrs
  if(pk != NULL && sk != NULL){
    memcpy(mt_intermediary.pk, *pk, SIZE_PK);
    memcpy(mt_intermediary.sk, *sk, SIZE_SK);
    pk_to_addr(pk, &mt_intermediary.addr);
  }

  // add provided channels to list
  mt_intermediary.channels = g_array_new();
  for(int i = 0; i < num_chns; i++){
    chn_end_data* chn = malloc(sizeof(chn_end_data));
    memcpy(chn, chns[i], sizeof(chn_end_data));
    g_array_append_val(mt_intermediary.channels, chn);
  }

  // establish circuit to ledger

}

int mt_intermediary_cashout(byte (*chn_addrs)[SIZE_PK]){
  // send first cell of request close to ledger
  // optional: connect to client/relay and warn them
}

int mt_intermediary_handle(cell_t *cell, circid_t* circ, edge_connection_t* conn, crypt_path_t *layer){

  ntype type; //= extract from cell
  int result;

  // process cells and compile into full on messages here if the message is complete
  byte* msg;

  switch(type){

    case NTYPE_CHN_END_ESTAB1:
      result = handle_chn_end_estab1(msg, circ, conn, layer);
      break;
    case NTYPE_CHN_END_ESTAB3:
      result = handle_chn_end_estab3(msg, circ, conn, layer);
      break;
    case NTYPE_MIC_CLI_PAY3:
      result = handle_mic_cli_pay3(msg, circ, conn, layer);
      break;
    case NTYPE_MIC_REV_PAY6:
      result = handle_mic_rev_pay6(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_CLI_SETUP1:
      result = handle_nan_cli_setup1(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_CLI_SETUP3:
      result = handle_nan_cli_setup3(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_CLI_SETUP5:
      result = handle_nan_cli_setup5(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_REL_ESTAB2:
      result = handle_nan_rel_estab2(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_REL_ESTAB4:
      result = handle_nan_rel_estab4(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_INT_ESTAB5:
      result = handle_nan_int_estab5(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_END_CLOSE1:
      result = handle_nan_end_close1(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_END_CLOSE3:
      result = handle_nan_end_close3(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_END_CLOSE5:
      result = handle_nan_end_close5(msg, circ, conn, layer);
      break;
    case NTYPE_NAN_END_CLOSE7:
      result = handle_nan_end_close7(msg, circ, conn, layer);
      break;
    case NTYPE_MAC_LED_QUERY:
      result = handle_mac_led_query(msg, circ, conn, layer);
      break;
    case NTYPE_CHN_LED_QUERY:
      result = handle_chn_led_query(msg, circ, conn, layer);
      break;
    default:
      result = MT_ERROR;
  }
}

int handle_chn_end_estab1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_chn_end_estab3(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mic_cli_pay3(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mic_rev_pay6(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_cli_setup1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_cli_setup3(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_cli_setup5(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_rel_estab2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_rel_estab4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_int_estab5(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_end_close1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_end_close3(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_end_close5(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_nan_end_close7(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_mac_led_query(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}
int handle_chn_led_query(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer){}




int node_is_intermediary(const node_t *node) {

  tor_assert(node);
  return (node->is_intermediary &&
      node->is_valid &&
      node->is_fast &&
      node->is_stable);
}
