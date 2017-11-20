#ifndef mt_intermediary_h
#define mt_intermediary_h

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
} mt_intermediary;

// Tor-facing API
int mt_intermediary_init(mt_intermediary* intermediary, byte (*pk)[SIZE_PK], byte (*sk)[SIZE_SIZE],
    chn_end_data* chn_data, int num_chns, mt_pay_cb* pay, mt_send_cb* send);
int mt_intermediary_cashout(mt_intermediary* intermediary, byte (*chn_addrs)[SIZE_ADDR]);
int mt_intermediary_handle(mt_intermediary* intermediary, cell_t* cell, mt_ctx* ctx);

// local handler functions
int handle_chn_end_estab1(mt_intermediary* intermediary, chn_end_estab1* token, mt_ctx* ctx);
int handle_chn_end_estab3(mt_intermediary* intermediary, chn_end_estab3* token, mt_ctx* ctx);
int handle_mic_cli_pay3(mt_intermediary* intermediary, mic_cli_pay3* token, mt_ctx* ctx);
int handle_mic_rev_pay6(mt_intermediary* intermediary, mic_rev_pay6* token, mt_ctx* ctx);
int handle_nan_cli_setup1(mt_intermediary* intermediary, nan_cli_setup1* token, mt_ctx* ctx);
int handle_nan_cli_setup3(mt_intermediary* intermediary, nan_cli_setup3* token, mt_ctx* ctx);
int handle_nan_cli_setup5(mt_intermediary* intermediary, nan_cli_setup5* token, mt_ctx* ctx);
int handle_nan_rel_estab2(mt_intermediary* intermediary, nan_rel_estab2* token, mt_ctx* ctx);
int handle_nan_rel_estab4(mt_intermediary* intermediary, nan_rel_estab4* token, mt_ctx* ctx);
int handle_nan_int_estab5(mt_intermediary* intermediary, nan_int_estab5* token, mt_ctx* ctx);
int handle_nan_end_close1(mt_intermediary* intermediary, nan_end_close1* token, mt_ctx* ctx);
int handle_nan_end_close3(mt_intermediary* intermediary, nan_end_close3* token, mt_ctx* ctx);
int handle_nan_end_close5(mt_intermediary* intermediary, nan_end_close5* token, mt_ctx* ctx);
int handle_nan_end_close7(mt_intermediary* intermediary, nan_end_close7* token, mt_ctx* ctx);
int handle_mac_led_query(mt_intermediary* intermediary, mac_led_query* token, mt_ctx* ctx);
int handle_chn_led_query(mt_intermediary* intermediary, chn_led_query* token, mt_ctx* ctx);


int node_is_intermediary(const node_t *node);

#endif
