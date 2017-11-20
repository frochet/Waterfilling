#ifndef mt_relay_h
#define mt_relay_h

#include "mt.h"
#include "mt_crypto.h"
#include "mt_tokens.h"

typedef struct{
    mt_pay_cb* pay;
    mt_send_cb* send;

    pk[SIZE_PK];
    sk[SIZE_SK];
    addr[SIZE_ADDR];

    GArray* channels;
} mt_relay;

// Tor-facing API
int mt_relay_init(mt_relay* relay, byte (*pk)[SIZE_PK], byte (*sk)[SIZE_SIZE],
		   chn_end_data* chn_data, int num_chns, mt_pay_cb* pay, mt_send_cb* send);
int mt_relay_cashout(mt_relay* relay, byte (*chn_addrs)[SIZE_ADDR]);
int mt_relay_handle(mt_relay* relay, cell_t* cell, mt_ctx* ctx);

// local handler functions
int handle_chn_int_estab2(mt_relay* relay, chn_int_estab2* token, mt_ctx* ctx);
int handle_chn_int_estab4(mt_relay* relay, chn_int_estab4* token, mt_ctx* ctx);
int handle_mic_cli_pay1(mt_relay* relay, mic_cli_pay1* token, mt_ctx* ctx);
int handle_mic_cli_pay5(mt_relay* relay, mic_cli_pay5* token, mt_ctx* ctx);
int handle_mic_int_pay8(mt_relay* relay, mic_int_pay8* token, mt_ctx* ctx);
int handle_nan_cli_estab1(mt_relay* relay, nan_cli_estab1* token, mt_ctx* ctx);
int handle_nan_int_estab3(mt_relay* relay, nan_int_estab3* token, mt_ctx* ctx);
int handle_nan_int_estab5(mt_relay* relay, nan_int_estab5* token, mt_ctx* ctx);
int handle_nan_cli_pay1(mt_relay* relay, nan_cli_pay1* token, mt_ctx* ctx);
int handle_nan_int_close2(mt_relay* relay, nan_int_close2* token, mt_ctx* ctx);
int handle_nan_int_close4(mt_relay* relay, nan_int_close4* token, mt_ctx* ctx);
int handle_nan_int_close6(mt_relay* relay, nan_int_close6* token, mt_ctx* ctx);
int handle_nan_int_close8(mt_relay* relay, nan_int_close8* token, mt_ctx* ctx);
int handle_mac_led_data(mt_relay* relay, mac_led_data* token, mt_ctx* ctx);
int handle_chn_led_data(mt_relay* relay, chn_led_data* token, mt_ctx* ctx);

#endif
