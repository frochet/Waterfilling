/**
 * \file mt_cpay.h
 * \brief Header file for mt_cpay.c
 **/

#include "or.h"
#include "mt_common.h"
#include "mt_cpay.h"


/*int handle_chn_int_estab2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_chn_int_estab4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_mic_cli_pay1(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_mic_rel_pay2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_mic_int_pay4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_mic_int_pay7(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_nan_int_setup2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_nan_int_setup4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_nan_int_setup6(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_nan_int_close2(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_nan_int_close4(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_nan_int_close6(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_nan_int_close8(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_mac_led_data(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/
/*int handle_chn_led_data(byte* msg, circuit_t* circ, edge_connection_t* conn, crypt_path_t* layer);*/

/*
//TODO:
//    rethink global variables
//    figure out which data structures we need to send info
//    modifiy handlers to accept tokens instead of messages
//    have all functions return list of cells + connection to send it to

//TODO: rethink end user / intermediary tokens
int mt_cpay_init(mt_cpay_t* client, byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK],
		   chn_end_data_t* chn_data, int num_chns){

  // record key and addrs

  // add provided channels to list

  // establish circuit to ledger

  // if we have not already connected with entry
  //    if we are out of open microchannels then create one
  //    send first cell of micro_establish with entry
  //    send first cell of nano_establish with entry

  return 0; // for compilation
}

int mt_cpay_establish(mt_cpay_t* client, circuit_t* circ){

  // if we do not have enough open channels
  //    send first cell of chn_init with the ledger
  //    send first cell of chn_establish with an intermediary

  // pop off available channel with lowest funds remaining
  // send first cell of nan_establish with remaining circuits
  return 0;
}

int mt_cpay_pay(mt_cpay_t* client, circuit_t* circ){
  // loop through all relays in circuit
  //    send nan_pay cell
  return 0;
}

int mt_cpay_close(mt_cpay_t* client, circuit_t* circ){
  // loop through middle and entry
  //     send first cell of nan_close with each
  return 0;
}

int mt_cpay_cashout(mt_cpay_t* client, byte (*chn_addrs)[MT_SZ_ADDR]){
  // send first cell of cashout protocol with ledger
  // optional: connect to intermediary/entry and warn them
  return 0;
}

int mt_cpay_handle(mt_cpay_t* client, cell_t* cell){}
*/
