#ifndef mt_tokens_h
#define mt_tokens_h

#include <glib.h>

#include "mt.h"

//TODO should probably put these in terms of Tor variables somewhere
#define CELL_SIZE 512

//-------------------------- Pack/Unpack Functions --------------------------//

// extract the token type from the packed message
mt_ntype_t token_type(cell_t* cell);

// convert semantically meaningful structs to sendable byte strings & sizes

int pack_mac_aut_mint(mac_aut_mint_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mac_any_trans(mac_any_trans_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_end_escrow(chn_end_escrow_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_int_escrow(chn_int_escrow_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_int_reqclose(chn_int_reqclose_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_end_close(chn_end_close_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_int_close(chn_int_close_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_end_cashout(chn_end_cashout_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_int_cashout(chn_int_cashout_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_mac_led_data(mac_led_data_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_led_data(chn_led_data_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mac_led_query(mac_led_query_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_led_query(chn_led_query_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_chn_end_estab1(chn_end_estab1_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_int_estab2(chn_int_estab2_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_end_estab3(chn_end_estab3_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_chn_int_estab4(chn_int_estab4_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_mic_cli_pay1(mic_cli_pay1_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mic_rel_pay2(mic_rel_pay2_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mic_cli_pay3(mic_cli_pay3_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mic_int_pay4(mic_int_pay4_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mic_cli_pay5(mic_cli_pay5_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mic_rev_pay6(mic_rev_pay6_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mic_int_pay7(mic_int_pay7_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_mic_int_pay8(mic_int_pay8_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_nan_cli_setup1(nan_cli_setup1_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_setup2(nan_int_setup2_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_cli_setup3(nan_cli_setup3_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_setup4(nan_int_setup4_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_cli_setup5(nan_cli_setup5_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_setup6(nan_int_setup6_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_nan_cli_direct1(nan_cli_direct1_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_direct2(nan_int_direct2_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_nan_cli_estab1(nan_cli_estab1_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_rel_estab2(nan_rel_estab2_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_estab3(nan_int_estab3_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_rel_estab4(nan_rel_estab4_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_estab5(nan_int_estab5_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_nan_cli_pay1(nan_cli_pay1_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

int pack_nan_end_close1(nan_end_close1_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_close2(nan_int_close2_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_end_close3(nan_end_close3_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_close4(nan_int_close4_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_end_close5(nan_end_close5_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_close6(nan_int_close6_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_end_close7(nan_end_close7_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);
int pack_nan_int_close8(nan_int_close8_t tkn, byte(*pk)[MT_SZ_PK], byte(*sk)[MT_SZ_SK], cell_t** c_out);

// convert sendable byte strings to semantically meaningful structs

int unpack_mac_aut_mint(cell_t* cell, mac_aut_mint_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mac_any_trans(cell_t* cell, mac_any_trans_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_end_escrow(cell_t* cell, chn_end_escrow_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_int_escrow(cell_t* cell, chn_int_escrow_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_int_reqclose(cell_t* cell, chn_int_reqclose_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_end_close(cell_t* cell, chn_end_close_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_int_close(cell_t* cell, chn_int_close_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_end_cashout(cell_t* cell, chn_end_cashout_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_int_cashout(cell_t* cell, chn_int_cashout_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_mac_led_data(cell_t* cell, mac_led_data_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_led_data(cell_t* cell, chn_led_data_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mac_led_query(cell_t* cell, mac_led_query_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_led_query(cell_t* cell, chn_led_query_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_chn_end_estab1(cell_t* cell, chn_end_estab1_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_int_estab2(cell_t* cell, chn_int_estab2_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_end_estab3(cell_t* cell, chn_end_estab3_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_chn_int_estab4(cell_t* cell, chn_int_estab4_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_mic_cli_pay1(cell_t* cell, mic_cli_pay1_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mic_rel_pay2(cell_t* cell, mic_rel_pay2_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mic_cli_pay3(cell_t* cell, mic_cli_pay3_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mic_int_pay4(cell_t* cell, mic_int_pay4_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mic_cli_pay5(cell_t* cell, mic_cli_pay5_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mic_rev_pay6(cell_t* cell, mic_rev_pay6_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mic_int_pay7(cell_t* cell, mic_int_pay7_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_mic_int_pay8(cell_t* cell, mic_int_pay8_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_nan_cli_setup1(cell_t* cell, nan_cli_setup1_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_setup2(cell_t* cell, nan_int_setup2_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_cli_setup3(cell_t* cell, nan_cli_setup3_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_setup4(cell_t* cell, nan_int_setup4_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_cli_setup5(cell_t* cell, nan_cli_setup5_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_setup6(cell_t* cell, nan_int_setup6_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_nan_cli_direct1(cell_t* cell, nan_cli_direct1_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_direct2(cell_t* cell, nan_int_direct2_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_nan_cli_estab1(cell_t* cell, nan_cli_estab1_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_rel_estab2(cell_t* cell, nan_rel_estab2_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_estab3(cell_t* cell, nan_int_estab3_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_rel_estab4(cell_t* cell, nan_rel_estab4_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_estab5(cell_t* cell, nan_int_estab5_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_nan_cli_pay1(cell_t* cell, nan_cli_pay1_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

int unpack_nan_end_close1(cell_t* cell, nan_end_close1_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_close2(cell_t* cell, nan_int_close2_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_end_close3(cell_t* cell, nan_end_close3_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_close4(cell_t* cell, nan_int_close4_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_end_close5(cell_t* cell, nan_end_close5_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_close6(cell_t* cell, nan_int_close6_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_end_close7(cell_t* cell, nan_end_close7_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);
int unpack_nan_int_close8(cell_t* cell, nan_int_close8_t* tkn_out, byte(*pk_out)[MT_SZ_PK]);

#endif
