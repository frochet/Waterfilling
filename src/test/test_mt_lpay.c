#pragma GCC diagnostic ignored "-Wswitch-enum"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_common.h"
#include "mt_lpay.h"
#include "test.h"

int send_intercept_1;
int send_intercept_2;

int send_msg(mt_desc_t desc, mt_ntype_t type, byte* msg, int size);
int send_msg(mt_desc_t desc, mt_ntype_t type, byte* msg, int size){
  (void)desc;
  (void)type;
  (void)msg;
  (void)size;
  return 0;
  /*
  byte pk_discard[MT_SZ_PK];

  switch(token_type(cells)){
    case MT_NTYPE_MAC_LED_DATA:;
      mac_led_data_t mac_data;
      int c_led_data_t mac_data_size = unpack_mac_led_data(cells, &mac_data, &pk_discard);
      send_intercept_1 = mac_data.balance;
      break;
    case MT_NTYPE_CHN_LED_DATA:;
      chn_led_data_t chn_data;
      int n_led_data_t chn_data_size = unpack_chn_led_data(cells, &chn_data, &pk_discard);
      send_intercept_1 = chn_data.end_balance;
      send_intercept_2 = chn_data.int_balance;
      break;
    default:
      tt_assert(1 == 2);
      }*/
  return 0;
}

int close_conn(mt_desc_t desc);
int close_conn(mt_desc_t desc){
  (void)desc;
  return 0;
}

static int send_ledger(byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK], mt_desc_t* desc, mt_ntype_t type, void* tkn){

  byte proto_id[DIGEST_LEN];
  mt_crypt_rand_bytes(DIGEST_LEN, proto_id);

  byte* packed_msg;
  int packed_msg_size;

  switch(type){
    case MT_NTYPE_MAC_AUT_MINT:
      packed_msg_size = pack_mac_aut_mint((mac_aut_mint_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_MAC_ANY_TRANS:
      packed_msg_size = pack_mac_any_trans((mac_any_trans_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_END_ESCROW:
      packed_msg_size = pack_chn_end_escrow((chn_end_escrow_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_ESCROW:
      packed_msg_size = pack_chn_int_escrow((chn_int_escrow_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_REQCLOSE:
      packed_msg_size = pack_chn_int_reqclose((chn_int_reqclose_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_END_CLOSE:
      packed_msg_size = pack_chn_end_close((chn_end_close_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_CLOSE:
      packed_msg_size = pack_chn_int_close((chn_int_close_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_END_CASHOUT:
      packed_msg_size = pack_chn_end_cashout((chn_end_cashout_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_CASHOUT:
      packed_msg_size = pack_chn_int_cashout((chn_int_cashout_t*)tkn, &proto_id, &packed_msg);
      break;
    default:
      packed_msg_size = MT_ERROR;
  }

  if(packed_msg_size == MT_ERROR)
    return MT_ERROR;

  byte* signed_msg;
  int signed_msg_size = mt_create_signed_msg(packed_msg, packed_msg_size, pk, sk, &signed_msg);

  if(signed_msg_size == MT_ERROR){
    free(packed_msg);
    return MT_ERROR;
  }

  int result = mt_lpay_recv_message(desc, type, signed_msg, signed_msg_size);
  free(packed_msg);
  free(signed_msg);

  return result;
}


static void test_mt_lpay(void *arg)
{
  (void)arg;

  /* //----------------------------------- Setup ---------------------------------// */


  //TODO: read in payment parameters (pp/aut address) from seomwhere
  byte pp[MT_SZ_PP];   // bogus value; this should be read in from somewhere
  mt_lpay_init();

  // setup aut
  mt_payment_public_t public = mt_lpay_get_payment_public();
  mt_desc_t aut_0_desc = {.party = MT_PARTY_AUT};
  mt_crypt_rand_bytes(MT_SZ_ID, aut_0_desc.id);

  // set up end user
  byte end_1_pk[MT_SZ_PK];
  byte end_1_sk[MT_SZ_SK];
  byte end_1_addr[MT_SZ_ADDR];
  mt_desc_t end_1_desc = {.party = MT_PARTY_CLI};
  mt_crypt_keygen(&pp, &end_1_pk, &end_1_sk);
  mt_pk2addr(&end_1_pk, &end_1_addr);
  mt_crypt_rand_bytes(sizeof(end_1_desc), (byte*)&end_1_desc);

  // set up intermediary
  byte int_1_pk[MT_SZ_PK];
  byte int_1_sk[MT_SZ_SK];
  byte int_1_addr[MT_SZ_ADDR];
  mt_desc_t int_1_desc = {.party = MT_PARTY_INT};
  mt_crypt_keygen(&pp, &int_1_pk, &int_1_sk);
  mt_pk2addr(&int_1_pk, &int_1_addr);
  mt_crypt_rand_bytes(sizeof(int_1_desc), (byte*)&int_1_desc);

  // set up channel
  byte chn_1_addr[MT_SZ_ADDR];
  mt_crypt_rand_bytes(MT_SZ_ADDR, chn_1_addr);

  // hash chain for nanopayments
  int n = 1000;
  byte head[MT_SZ_HASH];
  byte hc[n][MT_SZ_HASH];
  mt_crypt_rand_bytes(MT_SZ_HASH, head);
  mt_hc_create(n, &head, &hc);
  int k = 58;

  byte aut_0_addr[MT_SZ_ADDR];
  mt_pk2addr(&public.auth_pk, &aut_0_addr);

  char aut_0_hex[MT_SZ_ADDR * 2 + 3] ;
  char end_1_hex[MT_SZ_ADDR * 2 + 3] ;
  char int_1_hex[MT_SZ_ADDR * 2 + 3] ;

  mt_addr2hex(&aut_0_addr, &aut_0_hex);
  mt_addr2hex(&end_1_addr, &end_1_hex);
  mt_addr2hex(&int_1_addr, &int_1_hex);

  printf("aut addr %s\n", aut_0_hex);
  printf("end addr %s\n", end_1_hex);
  printf("int addr %s\n", int_1_hex);

  //expected
  int exp_aut_0_bal = 0;
  int exp_end_1_bal = 0;
  int exp_int_1_bal = 0;
  int exp_end_1_esc = 0;
  int exp_int_1_esc = 0;

  //---------------------------------- Mint -----------------------------------//

  // Mint First Token
  int mint_val_1 = 1000 * 100;
  int mint_val_2 = 1500 * 100;

  exp_aut_0_bal = mint_val_1 + mint_val_2;

  // mint first token
  mac_aut_mint_t mint_1 = {.value = mint_val_1};
  tt_assert(send_ledger(&public.auth_pk, &public.auth_sk, &aut_0_desc, MT_NTYPE_MAC_AUT_MINT, &mint_1) == MT_SUCCESS);

  // mint second token
  mac_aut_mint_t mint_2 = {.value = mint_val_2};
  tt_assert(send_ledger(&public.auth_pk, &public.auth_sk, &aut_0_desc, MT_NTYPE_MAC_AUT_MINT, &mint_2) == MT_SUCCESS);

  //------------------------------ Transfer -----------------------------------//

  int end_val = 100 * 100;
  int int_val = 1000 * 100;

  exp_end_1_bal += end_val;
  exp_int_1_bal += int_val;
  exp_aut_0_bal -= end_val + int_val;

  // transfer to end user
  mac_any_trans_t end_trans = {.val_from = end_val + public.fee, .val_to = end_val};
  memcpy(end_trans.from, aut_0_addr, MT_SZ_ADDR);
  memcpy(end_trans.to, end_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&public.auth_pk, &public.auth_sk, &aut_0_desc, MT_NTYPE_MAC_ANY_TRANS, &end_trans) == MT_SUCCESS);

  // transfer to intermediary
  mac_any_trans_t int_trans = {.val_from = int_val + public.fee, .val_to = int_val};
  memcpy(int_trans.from, aut_0_addr, MT_SZ_ADDR);
  memcpy(int_trans.to, int_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&public.auth_pk, &public.auth_sk, &aut_0_desc, MT_NTYPE_MAC_ANY_TRANS, &int_trans) == MT_SUCCESS);

  //------------------------------- Post Escrow -------------------------------//

  int end_esc_val = 90 * 100;
  int int_esc_val = 900 * 100;

  exp_end_1_esc += end_esc_val;
  exp_int_1_esc += int_esc_val;
  exp_end_1_bal -= end_esc_val + public.fee;
  exp_int_1_bal -= int_esc_val + public.fee;
  exp_aut_0_bal += public.fee * 2;

  // end user escrow
  chn_end_escrow_t end_esc = {.val_from = end_esc_val + public.fee, .val_to =   end_esc_val};
  memcpy(end_esc.from, end_1_addr, MT_SZ_ADDR);
  memcpy(end_esc.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&end_1_pk, &end_1_sk, &end_1_desc, MT_NTYPE_CHN_END_ESCROW, &end_esc) == MT_SUCCESS);

  // intermediary escrow
  chn_int_escrow_t int_esc = {.val_from = int_esc_val + public.fee, .val_to = int_esc_val};
  memcpy(int_esc.from, int_1_addr, MT_SZ_ADDR);
  memcpy(int_esc.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_ESCROW, &int_esc) == MT_SUCCESS);

  //------------------------ Intermediary Request Close -----------------------//

  chn_int_reqclose_t int_reqclose;
  memcpy(int_reqclose.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_REQCLOSE, &int_reqclose) == MT_SUCCESS);


  //------------------------------ End User Close -----------------------------//

  chn_end_close_t end_close = {.last_pay_num = k};
  memcpy(end_close.chn, chn_1_addr, MT_SZ_ADDR);
  memcpy(end_close.last_hash, hc[k], MT_SZ_HASH);
  tt_assert(send_ledger(&end_1_pk, &end_1_sk, &end_1_desc, MT_NTYPE_CHN_END_CLOSE, &end_close) == MT_SUCCESS);

  //---------------------------- Intermediary Close ---------------------------//

  chn_int_close_t int_close = {.close_code = MT_CODE_ACCEPT, .last_pay_num = k};
  memcpy(int_close.chn, chn_1_addr, MT_SZ_ADDR);
  memcpy(int_close.last_hash, hc[k], MT_SZ_HASH);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_CLOSE, &int_close) == MT_SUCCESS);

  //-------------------------------- Cash Out ---------------------------------//

  int end_cashout_val = 50 * 100;
  int int_cashout_val = 50 * 100;

  exp_end_1_bal += end_cashout_val;
  exp_int_1_bal += int_cashout_val;
  exp_end_1_esc -= end_cashout_val + public.fee;
  exp_int_1_esc -= (int)((double)int_cashout_val + (double)public.fee + int_cashout_val * public.tax);
  exp_aut_0_bal += (int)((double)public.fee * 2 + int_cashout_val * public.tax);

  // end user cash out
  chn_end_cashout_t end_cashout = {.val_from = end_cashout_val + public.fee, .val_to = end_cashout_val};
  memcpy(end_cashout.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&end_1_pk, &end_1_sk, &end_1_desc, MT_NTYPE_CHN_END_CASHOUT, &end_cashout) == MT_SUCCESS);


  // intermediary cash out
  chn_int_cashout_t int_cashout;
  int_cashout.val_from = (int)((double)int_cashout_val + (double)public.fee + (int_cashout_val * public.tax));
  int_cashout.val_to = int_cashout_val;
  memcpy(int_cashout.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_CASHOUT, &int_cashout) == MT_SUCCESS);

  //------------------------------- Verify Balances ---------------------------//

  /* tt_assert(mt_lpay_query_mac_balance(&aut_0_addr) == exp_aut_0_bal); */
  /* tt_assert(mt_lpay_query_mac_balance(&end_1_addr) == exp_end_1_bal); */
  /* tt_assert(mt_lpay_query_mac_balance(&int_1_addr) == exp_int_1_bal); */
  /* tt_assert(mt_lpay_query_end_balance(&chn_1_addr) == exp_end_1_esc); */
  /* tt_assert(mt_lpay_query_int_balance(&chn_1_addr) == exp_int_1_esc); */

 done:;
}

struct testcase_t mt_lpay_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_lpay", test_mt_lpay, 0, NULL, NULL },
  END_OF_TESTCASES
};
