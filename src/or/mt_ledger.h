/**
 * \file mt_ledger.h
 * \brief Header file for mt_relay.c
 **/
#ifndef mt_ledger_h
#define mt_ledger_h

#include "mt.h"
#include "mt_tokens.h"

typedef struct {
    mt_send_cells send_cells;
    mt_close_conn close_conn;

    GTree* mac_accounts;
    GTree* chn_accounts;

    byte pp[MT_SZ_PP];
    int fee;
    double tax;
    int epoch;
    int close_window;

    byte roger_addr[MT_SZ_ADDR];
    byte led_pk[MT_SZ_PK];
    byte led_sk[MT_SZ_SK];
    byte led_addr[MT_SZ_ADDR];

} mt_ledger_t;

// Tor-facing API
int mt_ledger_init(mt_ledger_t* ledger, mt_send_cells send_cells, mt_close_conn close_conn, byte (*pp)[MT_SZ_PP], int fee, double  tax,  int close_window, byte (*roger_pk)[MT_SZ_PK]);
int mt_ledger_recv_cells(mt_ledger_t* ledger, cell_t* cell, mt_desc_t desc);

// transaction handles
int handle_mac_aut_mint(mt_ledger_t* ledger, mac_aut_mint_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_mac_any_trans(mt_ledger_t* ledger, mac_any_trans_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_chn_end_escrow(mt_ledger_t* ledger, chn_end_escrow_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_chn_int_escrow(mt_ledger_t* ledger, chn_int_escrow_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_chn_int_reqclose(mt_ledger_t* ledger, chn_int_reqclose_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_chn_end_close(mt_ledger_t* ledger, chn_end_close_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_chn_int_close(mt_ledger_t* ledger, chn_int_close_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_chn_end_cashout(mt_ledger_t* ledger, chn_end_cashout_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_chn_int_cashout(mt_ledger_t* ledger, chn_int_cashout_t* token, byte (*addr)[MT_SZ_ADDR]);
int handle_mac_led_query(mt_ledger_t* ledger, mac_led_query_t* token, mt_desc_t desc);
int handle_chn_led_query(mt_ledger_t* ledger, chn_led_query_t* token, mt_desc_t desc);

#endif
