#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "../mt.h"
#include "../mt_crypto.h"
#include "../mt_tokens.h"
#include "../mt_common.h"
#include "../mt_lpay.h"
#include "test_mt_main.h"

int send_intercept_1;
int send_intercept_2;

int send_cells(mt_desc_t desc, cell_t* cells, int num_cells){

    byte pk_discard[MT_SZ_PK];

    switch(token_type(cells)){
	case MT_NTYPE_MAC_LED_DATA:;
	    mac_led_data_t mac_data;
	    unpack_mac_led_data(cells, &mac_data, &pk_discard);
	    send_intercept_1 = mac_data.balance;
	    break;
	case MT_NTYPE_CHN_LED_DATA:;
	    chn_led_data_t chn_data;
	    unpack_chn_led_data(cells, &chn_data, &pk_discard);
	    send_intercept_1 = chn_data.end_balance;
	    send_intercept_2 = chn_data.int_balance;
	    break;
	default:
	    assert(1 == 2);
    }
    return 0;
}

int close_conn(mt_desc_t desc){
    return 0;
}

void test_mt_lpay(){

    //----------------------------------- Setup ---------------------------------//

    mt_lpay_t ledger;
    mt_desc_t desc = {.id = 1, .party = MT_PARTY_CLI};

    // pretend everything is in cents
    int fee = 5;
    double tax = 0.1;
    int close_window = 10;
    byte pp[MT_SZ_PP];

    mt_crypt_setup(&pp);

    // set up roger
    byte roger_pk[MT_SZ_PK];
    byte roger_sk[MT_SZ_SK];
    byte roger_addr[MT_SZ_ADDR];
    mt_crypt_keygen(&pp, &roger_pk, &roger_sk);
    mt_pk2addr(&roger_pk, &roger_addr);

    mt_lpay_init(&ledger, send_cells, close_conn, &pp, fee, tax, close_window, &roger_pk);

    // set up end user
    byte end_pk_1[MT_SZ_PK];
    byte end_sk_1[MT_SZ_SK];
    byte end_addr_1[MT_SZ_ADDR];
    mt_crypt_keygen(&pp, &end_pk_1, &end_sk_1);
    mt_pk2addr(&end_pk_1, &end_addr_1);

    // set up intermediary
    byte int_pk_1[MT_SZ_PK];
    byte int_sk_1[MT_SZ_SK];
    byte int_addr_1[MT_SZ_ADDR];
    mt_crypt_keygen(&pp, &int_pk_1, &int_sk_1);
    mt_pk2addr(&int_pk_1, &int_addr_1);

    // set up channel
    byte chn_addr[MT_SZ_ADDR];
    mt_crypt_rand_bytes(MT_SZ_ADDR, chn_addr);

    // hash chain for nanopayments
    int n = 1000;
    byte head[MT_SZ_HASH];
    byte hc[n][MT_SZ_HASH];
    mt_crypt_rand_bytes(MT_SZ_HASH, head);
    mt_hc_create(n, &head, &hc);
    int k = 58;

    char roger_hex[MT_SZ_ADDR * 2 + 3] ;
    char end_hex[MT_SZ_ADDR * 2 + 3] ;
    char int_hex[MT_SZ_ADDR * 2 + 3] ;

    mt_addr2hex(&roger_addr, &roger_hex);
    mt_addr2hex(&end_addr_1, &end_hex);
    mt_addr2hex(&int_addr_1, &int_hex);

    //printf("rog addr %s\n", roger_hex);
    //printf("end addr %s\n", end_hex);
    //printf("int addr %s\n", int_hex);

    //expected
    int exp_roger_bal = 0;
    int exp_end_1_bal = 0;
    int exp_int_1_bal = 0;
    int exp_end_1_esc = 0;
    int exp_int_1_esc = 0;

    //---------------------------------- Mint -----------------------------------//

    // mint first token
    int mint_val_1 = 1000 * 100;
    int mint_val_2 = 1500 * 100;

    exp_roger_bal = mint_val_1 + mint_val_2;

    mac_aut_mint_t mint_1 = {.value = mint_val_1};
    cell_t* mint_cells_1;
    pack_mac_aut_mint(mint_1, &roger_pk, &roger_sk, &mint_cells_1);
    assert(mt_lpay_recv_cells(&ledger, mint_cells_1, desc) == MT_SUCCESS);

    // mint second token
    mac_aut_mint_t mint_2 = {.value = mint_val_2};
    cell_t* mint_cells_2;
    pack_mac_aut_mint(mint_2, &roger_pk, &roger_sk, &mint_cells_2);
    assert(mt_lpay_recv_cells(&ledger, mint_cells_2, desc) == MT_SUCCESS);

    //------------------------------ Transfer -----------------------------------//

    int end_val = 100 * 100;
    int int_val = 1000 * 100;

    exp_end_1_bal += end_val;
    exp_int_1_bal += int_val;
    exp_roger_bal -= end_val + int_val;

    // transfer to end user
    mac_any_trans_t end_trans = {.val_from = end_val + fee, .val_to = end_val};
    memcpy(end_trans.from, roger_addr, MT_SZ_ADDR);
    memcpy(end_trans.to, end_addr_1, MT_SZ_ADDR);
    cell_t* end_trans_str;
    pack_mac_any_trans(end_trans, &roger_pk, &roger_sk, &end_trans_str);
    assert(mt_lpay_recv_cells(&ledger, end_trans_str, desc) == MT_SUCCESS);

    // transfer to intermediary
    mac_any_trans_t int_trans = {.val_from = int_val + fee, .val_to = int_val};
    memcpy(int_trans.from, roger_addr, MT_SZ_ADDR);
    memcpy(int_trans.to, int_addr_1, MT_SZ_ADDR);
    cell_t* int_trans_str;
    pack_mac_any_trans(int_trans, &roger_pk, &roger_sk, &int_trans_str);
    assert(mt_lpay_recv_cells(&ledger, int_trans_str, desc) == MT_SUCCESS);

    //------------------------------- Post Escrow -------------------------------//

    int end_esc_val = 90 * 100;
    int int_esc_val = 900 * 100;

    exp_end_1_esc += end_esc_val;
    exp_int_1_esc += int_esc_val;
    exp_end_1_bal -= end_esc_val + fee;
    exp_int_1_bal -= int_esc_val + fee;
    exp_roger_bal += fee * 2;

    // end user escrow
    chn_end_escrow_t end_esc = {.val_from = end_esc_val + fee, .val_to =   end_esc_val};
    memcpy(end_esc.from, end_addr_1, MT_SZ_ADDR);
    memcpy(end_esc.chn, chn_addr, MT_SZ_ADDR);
    // ignore channel token

    // send to ledger
    cell_t* end_esc_str;
    pack_chn_end_escrow(end_esc, &end_pk_1, &end_sk_1, &end_esc_str);
    assert(mt_lpay_recv_cells(&ledger, end_esc_str, desc) == MT_SUCCESS);

    // intermediary escrow
    chn_int_escrow_t int_esc = {.val_from = int_esc_val + fee, .val_to = int_esc_val};
    memcpy(int_esc.from, int_addr_1, MT_SZ_ADDR);
    memcpy(int_esc.chn, chn_addr, MT_SZ_ADDR);
    // ignore channel token

    // send to ledger
    cell_t* int_esc_str;
    pack_chn_int_escrow(int_esc, &int_pk_1, &int_sk_1, &int_esc_str);
    assert(mt_lpay_recv_cells(&ledger, int_esc_str, desc) == MT_SUCCESS);

    //------------------------ Intermediary Request Close -----------------------//

    chn_int_reqclose_t reqclose;
    memcpy(reqclose.chn, chn_addr, MT_SZ_ADDR);
    cell_t* reqclose_str;
    pack_chn_int_reqclose(reqclose, &int_pk_1, &int_sk_1, &reqclose_str);
    assert(mt_lpay_recv_cells(&ledger, reqclose_str, desc) == MT_SUCCESS);

    //------------------------------ End User Close -----------------------------//

    chn_end_close_t end_close = {.last_pay_num = k};
    memcpy(end_close.chn, chn_addr, MT_SZ_ADDR);
    memcpy(end_close.last_hash, hc[k], MT_SZ_HASH);
    cell_t* end_close_str;
    pack_chn_end_close(end_close, &end_pk_1, &end_sk_1, &end_close_str);
    assert(mt_lpay_recv_cells(&ledger, end_close_str, desc) == MT_SUCCESS);

    //---------------------------- Intermediary Close ---------------------------//

    chn_int_close_t int_close = {.close_code = MT_CODE_ACCEPT, .last_pay_num = k};
    memcpy(int_close.chn, chn_addr, MT_SZ_ADDR);
    memcpy(int_close.last_hash, hc[k], MT_SZ_HASH);
    cell_t* int_close_str;
    pack_chn_int_close(int_close, &int_pk_1, &int_sk_1, &int_close_str);
    assert(mt_lpay_recv_cells(&ledger, int_close_str, desc) == MT_SUCCESS);

    //-------------------------------- Cash Out ---------------------------------//

    int end_cashout_val = 50 * 100;
    int int_cashout_val = 50 * 100;

    exp_end_1_bal += end_cashout_val;
    exp_int_1_bal += int_cashout_val;
    exp_end_1_esc -= end_cashout_val + fee;
    exp_int_1_esc -= int_cashout_val + fee + int_cashout_val * tax;
    exp_roger_bal += fee * 2 + int_cashout_val * tax;

    // end user cash out
    chn_end_cashout_t end_cashout = {.val_from = end_cashout_val + fee, .val_to = end_cashout_val};
    memcpy(end_cashout.chn, chn_addr, MT_SZ_ADDR);
    cell_t* end_cashout_str;
    pack_chn_end_cashout(end_cashout, &end_pk_1, &end_sk_1, &end_cashout_str);
    assert(mt_lpay_recv_cells(&ledger, end_cashout_str, desc) == MT_SUCCESS);

    // intermediary cash out
    chn_int_cashout_t int_cashout;
    int_cashout.val_from = int_cashout_val + fee + (int_cashout_val * tax);
    int_cashout.val_to = int_cashout_val;
    memcpy(int_cashout.chn, chn_addr, MT_SZ_ADDR);
    cell_t* int_cashout_str;
    pack_chn_int_cashout(int_cashout, &int_pk_1, &int_sk_1, &int_cashout_str);
    assert(mt_lpay_recv_cells(&ledger, int_cashout_str, desc) == MT_SUCCESS);

    //---------------------------------- Query ----------------------------------//

    // query roger
    mac_led_query_t roger_query;
    cell_t* roger_query_cells;
    memcpy(&roger_query.addr, roger_addr, MT_SZ_ADDR);
    pack_mac_led_query(roger_query, &roger_pk, &roger_sk, &roger_query_cells);
    assert(mt_lpay_recv_cells(&ledger, roger_query_cells, desc) == MT_SUCCESS);
    assert(send_intercept_1 == exp_roger_bal);

    // query end user
    mac_led_query_t end_query;
    cell_t* end_query_cells;
    memcpy(&end_query.addr, end_addr_1, MT_SZ_ADDR);
    pack_mac_led_query(end_query, &roger_pk, &roger_sk, &end_query_cells);
    assert(mt_lpay_recv_cells(&ledger, end_query_cells, desc) == MT_SUCCESS);
    assert(send_intercept_1 == exp_end_1_bal);

    // query intermediary
    mac_led_query_t int_query;
    cell_t* int_query_cells;
    memcpy(&int_query.addr, int_addr_1, MT_SZ_ADDR);
    pack_mac_led_query(int_query, &roger_pk, &roger_sk, &int_query_cells);
    assert(mt_lpay_recv_cells(&ledger, int_query_cells, desc) == MT_SUCCESS);
    assert(send_intercept_1 == exp_int_1_bal);

    // query channel
    chn_led_query_t chn_query;
    cell_t* chn_query_cells;
    memcpy(&chn_query.addr, chn_addr, MT_SZ_ADDR);
    pack_chn_led_query(chn_query, &roger_pk, &roger_sk, &chn_query_cells);
    assert(mt_lpay_recv_cells(&ledger, chn_query_cells, desc) == MT_SUCCESS);
    assert(send_intercept_1 == exp_end_1_esc);
    assert(send_intercept_2 == exp_int_1_esc);
}
