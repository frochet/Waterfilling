#include "mt_ipay.h"


/* // local handler functions */
/* static int handle_chn_end_estab1(mt_desc_t desc, chn_end_estab1_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_chn_end_estab3(mt_desc_t desc, chn_end_estab3_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_mic_cli_pay3(mt_desc_t desc, mic_cli_pay3_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_mic_rev_pay6(mt_desc_t desc, mic_rev_pay6_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_cli_setup1(mt_desc_t desc, nan_cli_setup1_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_cli_setup3(mt_desc_t desc, nan_cli_setup3_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_cli_setup5(mt_desc_t desc, nan_cli_setup5_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_rel_estab2(mt_desc_t desc, nan_rel_estab2_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_rel_estab4(mt_desc_t desc, nan_rel_estab4_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_int_estab5(mt_desc_t desc, nan_int_estab5_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_end_close1(mt_desc_t desc, nan_end_close1_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_end_close3(mt_desc_t desc, nan_end_close3_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_end_close5(mt_desc_t desc, nan_end_close5_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_nan_end_close7(mt_desc_t desc, nan_end_close7_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_mac_led_query(mt_desc_t desc, mac_led_query_t* token, byte (*pk)[MT_SZ_PK]); */
/* static int handle_chn_led_query(mt_desc_t desc, chn_led_query_t* token, byte (*pk)[MT_SZ_PK]); */

/* int mt_intermediary_init(mt_intermediary* intermediary, byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK], */
/* 			 chn_end_data_t* chn_data, int num_chns){ */
/*   // record key and addrs */

/*   // add provided channels to list */

/*   // establish circuit to ledger */

/* } */

/* int mt_intermediary_cashout(mt_intermediary* intermediary, byte (*chn_addrs)[MT_SZ_ADDR]){ */
/*   // send first cell of request close to ledger */
/*   // optional: connect to client/relay and warn them */
/* } */


/* int mt_intermediary_handle(cell_t *cell, circid_t* circ, edge_connection_t* conn, crypt_path_t *layer){ */

/*   ntype type; //= extract from cell */
/*   int result; */

/*   // process cells and compile into full on messages here if the message is complete */
/*   byte* msg; */

/*   switch(type){ */

/*     case NTYPE_CHN_END_ESTAB1: */
/*       result = handle_chn_end_estab1(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_CHN_END_ESTAB3: */
/*       result = handle_chn_end_estab3(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_MIC_CLI_PAY3: */
/*       result = handle_mic_cli_pay3(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_MIC_REV_PAY6: */
/*       result = handle_mic_rev_pay6(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_CLI_SETUP1: */
/*       result = handle_nan_cli_setup1(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_CLI_SETUP3: */
/*       result = handle_nan_cli_setup3(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_CLI_SETUP5: */
/*       result = handle_nan_cli_setup5(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_REL_ESTAB2: */
/*       result = handle_nan_rel_estab2(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_REL_ESTAB4: */
/*       result = handle_nan_rel_estab4(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_INT_ESTAB5: */
/*       result = handle_nan_int_estab5(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_END_CLOSE1: */
/*       result = handle_nan_end_close1(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_END_CLOSE3: */
/*       result = handle_nan_end_close3(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_END_CLOSE5: */
/*       result = handle_nan_end_close5(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_NAN_END_CLOSE7: */
/*       result = handle_nan_end_close7(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_MAC_LED_QUERY: */
/*       result = handle_mac_led_query(msg, circ, conn, layer); */
/*       break; */
/*     case NTYPE_CHN_LED_QUERY: */
/*       result = handle_chn_led_query(msg, circ, conn, layer); */
/*       break; */
/*     default: */
/*       result = MT_ERROR; */
/*   } */
/* } */

/* static int handle_chn_end_estab1(mt_desc_t desc, chn_end_estab1_t* token, byte (*pk)[MT_SZ_PK]){ */

/*   // check validity incoming message */

/*   chn_int_estab2_t response; */

/*   // fill response with correct values */

/*   byte* resp_msg; */
/*   int resp_size = pack_chn_int_estab2(response, intermediary->pk, intermediary->sk,  &response_msg); */
/*   mt_send_message(desc, MT_NTYPE_CHN_INT_ESTAB2, resp_msg, resp_size); */
/* } */

/* static int handle_chn_end_estab3(mt_desc_t desc, chn_end_estab3_t* token, byte (*pk)[MT_SZ_PK]){ */

/*   // check validity incoming message */

/*   chn_int_estab4_t response; */

/*   // fill response with correct values */

/*   byte* resp_msg; */
/*   int resp_size = pack_chn_int_estab4(response, intermediary->pk, intermediary->sk,  &response_msg); */
/*   mt_send_message(desc, MT_NTYPE_CHN_INT_ESTAB4, resp_msg, resp_size); */


/* } */

/* static int handle_mic_cli_pay3(mt_desc_t desc, mic_cli_pay3_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_mic_rev_pay6(mt_desc_t desc, mic_rev_pay6_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_cli_setup1(mt_desc_t desc, nan_cli_setup1_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_cli_setup3(mt_desc_t desc, nan_cli_setup3_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_cli_setup5(mt_desc_t desc, nan_cli_setup5_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_rel_estab2(mt_desc_t desc, nan_rel_estab2_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_rel_estab4(mt_desc_t desc, nan_rel_estab4_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_int_estab5(mt_desc_t desc, nan_int_estab5_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_end_close1(mt_desc_t desc, nan_end_close1_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_end_close3(mt_desc_t desc, nan_end_close3_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_end_close5(mt_desc_t desc, nan_end_close5_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_nan_end_close7(mt_desc_t desc, nan_end_close7_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_mac_led_query(mt_desc_t desc, mac_led_query_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */

/* static int handle_chn_led_query(mt_desc_t desc, chn_led_query_t* token, byte (*pk)[MT_SZ_PK]){ */

/* } */
