#include <stdio.h>
#include <unistd.h>

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_common.h"
#include "mt_lpay.h"
#include "mt_cpay.h"
#include "mt_rpay.h"
#include "mt_ipay.h"
#include "test.h"

// declared here to be visible for mock_send_message
static mt_desc_t aut_desc;
static mt_desc_t led_desc;
static mt_desc_t cli_desc;
static mt_desc_t rel_desc;
static mt_desc_t int_desc;

// needed so send_message can track where the current message should be coming from
static mt_desc_t cur_desc;
static mt_desc_t old_desc;

static int mock_send_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size){

  mt_desc_t temp_desc;
  memcpy(&temp_desc, desc, sizeof(mt_desc_t));
  memcpy(&old_desc, &cur_desc, sizeof(mt_desc_t));
  memcpy(&cur_desc, &temp_desc, sizeof(mt_desc_t));

  const char* type_str;
  const char* party_str;

  switch(type){
    case MT_NTYPE_CHN_END_ESTAB1:
      type_str = "chn_end_estab1";
      break;
    case MT_NTYPE_CHN_INT_ESTAB2:
      type_str = "chn_int_estab2";
      break;
    case MT_NTYPE_CHN_END_ESTAB3:
      type_str = "chn_end_estab3";
      break;
    case MT_NTYPE_CHN_INT_ESTAB4:
      type_str = "chn_int_estab4";
      break;
    case MT_NTYPE_MIC_CLI_PAY1:
      type_str = "mic_cli_pay1";
      break;
    case MT_NTYPE_MIC_REL_PAY2:
      type_str = "mic_rel_pay2";
      break;
    case MT_NTYPE_MIC_CLI_PAY3:
      type_str = "mic_cli_pay3";
      break;
    case MT_NTYPE_MIC_INT_PAY4:
      type_str = "mic_int_pay4";
      break;
    case MT_NTYPE_MIC_CLI_PAY5:
      type_str = "mic_cli_pay5";
      break;
    case MT_NTYPE_MIC_REV_PAY6:
      type_str = "mic_rev_pay6";
      break;
    case MT_NTYPE_MIC_INT_PAY7:
      type_str = "mic_int_pay7";
      break;
    case MT_NTYPE_MIC_INT_PAY8:
      type_str = "mic_int_pay8";
      break;
    case MT_NTYPE_NAN_CLI_SETUP1:
      type_str = "nan_cli_setup1";
      break;
    case MT_NTYPE_NAN_INT_SETUP2:
      type_str = "nan_int_setup2";
      break;
    case MT_NTYPE_NAN_CLI_SETUP3:
      type_str = "nan_cli_setup3";
      break;
    case MT_NTYPE_NAN_INT_SETUP4:
      type_str = "nan_int_setup4";
      break;
    case MT_NTYPE_NAN_CLI_SETUP5:
      type_str = "nan_cli_setup5";
      break;
    case MT_NTYPE_NAN_INT_SETUP6:
      type_str = "nan_int_setup6";
      break;
    case MT_NTYPE_NAN_CLI_DESTAB1:
      type_str = "nan_cli_destab1";
      break;
    case MT_NTYPE_NAN_INT_DESTAB2:
      type_str = "nan_int_destab2";
      break;
    case MT_NTYPE_NAN_CLI_DPAY1:
      type_str = "nan_cli_dpay1";
      break;
    case MT_NTYPE_NAN_INT_DPAY2:
      type_str = "nan_int_dpay2";
      break;
    case MT_NTYPE_NAN_CLI_ESTAB1:
      type_str = "nan_cli_estab1";
      break;
    case MT_NTYPE_NAN_REL_ESTAB2:
      type_str = "nan_rel_estab2";
      break;
    case MT_NTYPE_NAN_INT_ESTAB3:
      type_str = "nan_int_estab3";
      break;
    case MT_NTYPE_NAN_REL_ESTAB4:
      type_str = "nan_rel_estab4";
      break;
    case MT_NTYPE_NAN_INT_ESTAB5:
      type_str = "nan_int_estab5";
      break;
    case MT_NTYPE_NAN_REL_ESTAB6:
      type_str = "nan_rel_estab6";
      break;
    case MT_NTYPE_NAN_CLI_PAY1:
      type_str = "nan_cli_pay1";
      break;
    case MT_NTYPE_NAN_REL_PAY2:
      type_str = "nan_rel_pay2";
      break;
    case MT_NTYPE_NAN_CLI_REQCLOSE1:
      type_str = "nan_cli_reqclose1";
      break;
    case MT_NTYPE_NAN_REL_REQCLOSE2:
      type_str = "nan_rel_reqclose2";
      break;
    case MT_NTYPE_NAN_END_CLOSE1:
      type_str = "nan_end_close1";
      break;
    case MT_NTYPE_NAN_INT_CLOSE2:
      type_str = "nan_int_close2";
      break;
    case MT_NTYPE_NAN_END_CLOSE3:
      type_str = "nan_end_close3";
      break;
    case MT_NTYPE_NAN_INT_CLOSE4:
      type_str = "nan_int_close4";
      break;
    case MT_NTYPE_NAN_END_CLOSE5:
      type_str = "nan_end_close5";
      break;
    case MT_NTYPE_NAN_INT_CLOSE6:
      type_str = "nan_int_close6";
      break;
    case MT_NTYPE_NAN_END_CLOSE7:
      type_str = "nan_end_close7";
      break;
    case MT_NTYPE_NAN_INT_CLOSE8:
      type_str = "nan_int_close8";
      break;
    case MT_NTYPE_MAC_AUT_MINT:
      type_str = "mac_aut_mint";
      break;
    case MT_NTYPE_MAC_ANY_TRANS:
      type_str = "mac_any_trans";
      break;
    case MT_NTYPE_CHN_END_SETUP:
      type_str = "chn_end_setup";
      break;
    case MT_NTYPE_CHN_INT_SETUP:
      type_str = "chn_int_setup";
      break;
    case MT_NTYPE_CHN_INT_REQCLOSE:
      type_str = "chn_int_reqclose";
      break;
    case MT_NTYPE_CHN_END_CLOSE:
      type_str = "chn_end_close";
      break;
    case MT_NTYPE_CHN_INT_CLOSE:
      type_str = "chn_int_close";
      break;
    case MT_NTYPE_CHN_END_CASHOUT:
      type_str = "chn_end_cashout";
      break;
    case MT_NTYPE_CHN_INT_CASHOUT:
      type_str = "chn_int_cashout";
      break;
    case MT_NTYPE_ANY_LED_CONFIRM:
      type_str = "any_led_confirm";
      break;
    case MT_NTYPE_MAC_LED_DATA:
      type_str = "mac_led_data";
      break;
    case MT_NTYPE_CHN_LED_DATA:
      type_str = "chn_led_data";
      break;
    case MT_NTYPE_MAC_LED_QUERY:
      type_str = "mac_led_query";
      break;
    case MT_NTYPE_CHN_LED_QUERY:
      type_str = "chn_led_query";
      break;
  }

  switch(old_desc.party){
    case MT_PARTY_AUT:
      party_str = "aut";
      break;
    case MT_PARTY_LED:
      party_str = "led";
      break;
    case MT_PARTY_CLI:
      party_str = "cli";
      break;
    case MT_PARTY_REL:
      party_str = "rel";
      break;
    case MT_PARTY_INT:
      party_str = "int";
      break;
  }

  if(memcmp(cur_desc.id, aut_desc.id, MT_SZ_ID) == 0 && cur_desc.party == MT_PARTY_AUT){
    printf("%s -> aut : %s\n", party_str, type_str);
    return MT_SUCCESS;
  }

  if(memcmp(cur_desc.id, led_desc.id, MT_SZ_ID) == 0 && cur_desc.party == MT_PARTY_LED){
    printf("%s -> led : %s\n", party_str, type_str);
    return mt_lpay_recv(&old_desc, type, msg, size);
  }

  if(memcmp(cur_desc.id, cli_desc.id, MT_SZ_ID) == 0 && cur_desc.party == MT_PARTY_CLI){
    printf("%s -> cli : %s\n", party_str, type_str);
    return mt_cpay_recv(&old_desc, type, msg, size);
  }

  if(memcmp(cur_desc.id, rel_desc.id, MT_SZ_ID) == 0 && cur_desc.party == MT_PARTY_REL){
    printf("%s -> rel : %s\n", party_str, type_str);
    return mt_rpay_recv(&old_desc, type, msg, size);
  }

  if(memcmp(cur_desc.id, int_desc.id, MT_SZ_ID) == 0 && cur_desc.party == MT_PARTY_INT){
    printf("%s -> int : %s\n", party_str, type_str);
    return mt_ipay_recv(&old_desc, type, msg, size);
  }

  printf("ERROR: descriptor not recognized\n");
  return MT_ERROR;
}

static int mock_send_message_multidesc(mt_desc_t *desc1, mt_desc_t* desc2, mt_ntype_t type, byte* msg, int size){
  mt_desc_t temp_desc;
  memcpy(&temp_desc, desc1, sizeof(mt_desc_t));
  memcpy(&old_desc, &cur_desc, sizeof(mt_desc_t));
  memcpy(&cur_desc, &temp_desc, sizeof(mt_desc_t));

  if(memcmp(cur_desc.id, rel_desc.id, MT_SZ_ID) == 0
     && cur_desc.party == MT_PARTY_REL
     && type == MT_NTYPE_NAN_CLI_ESTAB1){
    printf("cli - >rel : nan_cli_estab1\n");
    return mt_rpay_recv_multidesc(&old_desc, desc2, type, msg, size);
  }
}


static int mock_alert_payment(mt_desc_t* desc){
  (void)desc;
  printf("payment successful\n");
  return MT_SUCCESS;
}

static int mock_new_intermediary(mt_desc_t* desc){
  memcpy(desc, &int_desc, sizeof(mt_desc_t));
  return MT_SUCCESS;
}

static void write_file(const char* name, void* buf, int size){
  FILE *fp;
  fp = fopen(name, "wb");
  fwrite(buf, sizeof(byte), size, fp);
  fclose(fp);
}

static void test_mt_paysimple(void *arg){

  printf("\n\n------------ begin paysimple ------------\n\n");

  (void)arg;

  MOCK(mt_send_message, mock_send_message);
  MOCK(mt_send_message_multidesc, mock_send_message_multidesc);
  MOCK(mt_alert_payment, mock_alert_payment);
  MOCK(mt_new_intermediary, mock_new_intermediary);

  /****************************** Setup **********************************/

  // account infos for each party
  byte pp[MT_SZ_PP];
  byte aut_pk[MT_SZ_PK];
  byte aut_sk[MT_SZ_SK];
  aut_desc.party = MT_PARTY_AUT;

  byte led_pk[MT_SZ_PK];
  byte led_sk[MT_SZ_SK];
  led_desc.party = MT_PARTY_LED;

  byte cli_pk[MT_SZ_PK];
  byte cli_sk[MT_SZ_SK];
  cli_desc.party = MT_PARTY_CLI;

  byte rel_pk[MT_SZ_PK];
  byte rel_sk[MT_SZ_SK];
  rel_desc.party = MT_PARTY_REL;

  byte int_pk[MT_SZ_PK];
  byte int_sk[MT_SZ_SK];
  int_desc.party = MT_PARTY_INT;

  // fill in account info
  mt_crypt_setup(&pp);

  mt_crypt_keygen(&pp, &aut_pk, &aut_sk);
  mt_crypt_keygen(&pp, &led_pk, &led_sk);
  mt_crypt_keygen(&pp, &cli_pk, &cli_sk);
  mt_crypt_keygen(&pp, &rel_pk, &rel_sk);
  mt_crypt_keygen(&pp, &int_pk, &int_sk);

  mt_crypt_rand(MT_SZ_ID, led_desc.id);
  mt_crypt_rand(MT_SZ_ID, cli_desc.id);
  mt_crypt_rand(MT_SZ_ID, rel_desc.id);
  mt_crypt_rand(MT_SZ_ID, int_desc.id);

  // write to files TODO: this should be done via torrc instead
  write_file("mt_config_temp/pp", pp, MT_SZ_PP);

  write_file("mt_config_temp/aut_pk", aut_pk, MT_SZ_PK);
  write_file("mt_config_temp/aut_sk", aut_sk, MT_SZ_SK);
  write_file("mt_config_temp/aut_desc", &aut_desc, sizeof(mt_desc_t));

  write_file("mt_config_temp/led_pk", led_pk, MT_SZ_PK);
  write_file("mt_config_temp/led_sk", led_sk, MT_SZ_SK);
  write_file("mt_config_temp/led_desc", &led_desc, sizeof(mt_desc_t));

  write_file("mt_config_temp/cli_pk", cli_pk, MT_SZ_PK);
  write_file("mt_config_temp/cli_sk", cli_sk, MT_SZ_SK);
  write_file("mt_config_temp/cli_desc", &cli_desc, sizeof(mt_desc_t));

  write_file("mt_config_temp/rel_pk", rel_pk, MT_SZ_PK);
  write_file("mt_config_temp/rel_sk", rel_sk, MT_SZ_SK);
  write_file("mt_config_temp/rel_desc", &rel_desc, sizeof(mt_desc_t));

  write_file("mt_config_temp/int_pk", int_pk, MT_SZ_PK);
  write_file("mt_config_temp/int_sk", int_sk, MT_SZ_SK);
  write_file("mt_config_temp/int_desc", &int_desc, sizeof(mt_desc_t));

  // calculate ledger addresses
  byte aut_addr[MT_SZ_ADDR];
  byte led_addr[MT_SZ_ADDR];
  byte cli_addr[MT_SZ_ADDR];
  byte rel_addr[MT_SZ_ADDR];
  byte int_addr[MT_SZ_ADDR];

  mt_pk2addr(&aut_pk, &aut_addr);
  mt_pk2addr(&led_pk, &led_addr);
  mt_pk2addr(&cli_pk, &cli_addr);
  mt_pk2addr(&rel_pk, &rel_addr);
  mt_pk2addr(&int_pk, &int_addr);

  // initialize all payment modules
  tt_assert(mt_lpay_init() == MT_SUCCESS);
  tt_assert(mt_cpay_init() == MT_SUCCESS);
  tt_assert(mt_ipay_init() == MT_SUCCESS);
  tt_assert(mt_rpay_init() == MT_SUCCESS);

  mt_payment_public_t public = mt_lpay_get_payment_public();

  int result;

  // mint money
  int mint_val = 1000 * 100;
  mac_aut_mint_t mint = {.value = mint_val};
  byte mint_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, mint_id);

  byte* packed_mint;
  byte* signed_mint;
  int packed_mint_size = pack_mac_aut_mint(&mint, &mint_id, &packed_mint);
  int signed_mint_size = mt_create_signed_msg(packed_mint, packed_mint_size,
					      &aut_pk, &aut_sk, &signed_mint);

  memcpy(&cur_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_AUT_MINT, signed_mint, signed_mint_size);
  tt_assert(result == MT_SUCCESS);

  // send money to client
  int cli_trans_val = 500 * 100;
  mac_any_trans_t cli_trans = {.val_to = cli_trans_val, .val_from = cli_trans_val + public.fee};
  memcpy(cli_trans.from, aut_addr, MT_SZ_ADDR);
  memcpy(cli_trans.to, cli_addr, MT_SZ_ADDR);
  byte cli_trans_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, cli_trans_id);

  byte* packed_cli_trans;
  byte* signed_cli_trans;
  int packed_cli_trans_size = pack_mac_any_trans(&cli_trans, &cli_trans_id, &packed_cli_trans);
  int signed_cli_trans_size = mt_create_signed_msg(packed_cli_trans, packed_cli_trans_size,
						   &aut_pk, &aut_sk, &signed_cli_trans);
  memcpy(&cur_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_ANY_TRANS, signed_cli_trans, signed_cli_trans_size);
  tt_assert(result == MT_SUCCESS);

  // send money to relay
  int rel_trans_val = 100 * 100;
  mac_any_trans_t rel_trans = {.val_to = rel_trans_val, .val_from = rel_trans_val + public.fee};
  memcpy(rel_trans.from, aut_addr, MT_SZ_ADDR);
  memcpy(rel_trans.to, rel_addr, MT_SZ_ADDR);
  byte rel_trans_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, rel_trans_id);

  byte* packed_rel_trans;
  byte* signed_rel_trans;
  int packed_rel_trans_size = pack_mac_any_trans(&rel_trans, &rel_trans_id, &packed_rel_trans);
  int signed_rel_trans_size = mt_create_signed_msg(packed_rel_trans, packed_rel_trans_size,
						   &aut_pk, &aut_sk, &signed_rel_trans);
  memcpy(&cur_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_ANY_TRANS, signed_rel_trans, signed_rel_trans_size);
  tt_assert(result == MT_SUCCESS);

  // send money to intermediary
  int int_trans_val = 100 * 100;
  mac_any_trans_t int_trans = {.val_to = int_trans_val, .val_from = int_trans_val + public.fee};
  memcpy(int_trans.from, aut_addr, MT_SZ_ADDR);
  memcpy(int_trans.to, int_addr, MT_SZ_ADDR);
  byte int_trans_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, int_trans_id);

  byte* packed_int_trans;
  byte* signed_int_trans;
  int packed_int_trans_size = pack_mac_any_trans(&int_trans, &int_trans_id, &packed_int_trans);
  int signed_int_trans_size = mt_create_signed_msg(packed_int_trans, packed_int_trans_size,
						   &aut_pk, &aut_sk, &signed_int_trans);
  memcpy(&cur_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_ANY_TRANS, signed_int_trans, signed_int_trans_size);
  tt_assert(result == MT_SUCCESS);

  // make sure balances are correct
  tt_assert(mt_lpay_query_mac_balance(&cli_addr) == cli_trans_val);
  tt_assert(mt_lpay_query_mac_balance(&rel_addr) == rel_trans_val);
  tt_assert(mt_lpay_query_mac_balance(&int_addr) == int_trans_val);

  /**************************** Protocol Tests ***************************/

  printf("\n");

  // pay relay
  memcpy(&cur_desc, &cli_desc, sizeof(mt_desc_t));
  tt_assert(mt_cpay_pay(&rel_desc) == MT_SUCCESS);

  // close channel

 done:;
  UNMOCK(mt_send_message);
  UNMOCK(mt_alert_payment);
  UNMOCK(mt_new_intermediary);

  printf("\n-------------- end paysimple ------------\n\n");

}

struct testcase_t mt_paysimple_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_paysimple", test_mt_paysimple, 0, NULL, NULL },
  END_OF_TESTCASES
};
