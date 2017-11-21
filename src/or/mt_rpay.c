#include "mt_rpay.h"

/* // local handler functions */
/* int handle_chn_int_estab2(mt_relay_t* relay, chn_int_estab2_t* token); */
/* int handle_chn_int_estab4(mt_relay_t* relay, chn_int_estab4_t* token); */
/* int handle_mic_cli_pay1(mt_relay_t* relay, mic_cli_pay1_t* token); */
/* int handle_mic_cli_pay5(mt_relay_t* relay, mic_cli_pay5_t* token); */
/* int handle_mic_int_pay8(mt_relay_t* relay, mic_int_pay8_t* token); */
/* int handle_nan_cli_estab1(mt_relay_t* relay, nan_cli_estab1_t* token); */
/* int handle_nan_int_estab3(mt_relay_t* relay, nan_int_estab3_t* token); */
/* int handle_nan_int_estab5(mt_relay_t* relay, nan_int_estab5_t* token); */
/* int handle_nan_cli_pay1(mt_relay_t* relay, nan_cli_pay1_t* token); */
/* int handle_nan_int_close2(mt_relay_t* relay, nan_int_close2_t* token); */
/* int handle_nan_int_close4(mt_relay_t* relay, nan_int_close4_t* token); */
/* int handle_nan_int_close6(mt_relay_t* relay, nan_int_close6_t* token); */
/* int handle_nan_int_close8(mt_relay_t* relay, nan_int_close8_t* token); */
/* int handle_mac_led_data(mt_relay_t* relay, mac_led_data_t* token); */
/* int handle_chn_led_data(mt_relay_t* relay, chn_led_data_t* token); */

/*
// Tor-facing API
int mt_relay_init(mt_relay_t* relay, byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK],
		  chn_end_data_t* chn_data, int num_chns){

    //record key and addrs
    // add provided channels to list
    // establish circuit to ledger
}

int mt_relay_cashout(byte (*chn_addrs)[MT_SZ_PK]){
    // send first cell of cashout protocol with ledger
    // optional: connect to intermediary/entry and warn them
}

int mt_relay_handle(mt_relay_t* relay, cell_t* cell,);
*/
