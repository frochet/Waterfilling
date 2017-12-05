#pragma GCC diagnostic ignored "-Wswitch-enum"
#pragma GCC diagnostic ignored "-Wunused-function"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "or.h"
#include "workqueue.h"
#include "cpuworker.h"
#include "mt_common.h"
#include "mt_cpay.h"

#define INIT_CHN_BALANCE 10 * 100;

typedef int (*mt_user_notify_t)(mt_desc_t*);

typedef enum {
  MT_ZKP_STATE_NONE,
  MT_ZKP_STATE_STARTED,
  MT_ZKP_STATE_READY,
} mt_zkp_state_t;

typedef struct {
  mt_desc_t rdesc;
  mt_desc_t idesc;
  chn_end_data_t data;

  mt_user_notify_t callback;
  mt_desc_t callback_desc;

  mt_zkp_state_t zkp_state;
} mt_channel_t;

/**
 * Single instance of a client payment object
 */
typedef struct {

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte addr[MT_SZ_ADDR];

  mt_desc_t ledger;
  int fee;

  smartlist_t* chns_setup;
  smartlist_t* chns_estab;
  smartlist_t* nans_setup;
  digestmap_t* nans_estab;        // desc -> channel
  digestmap_t* nans_reqclosed;    // desc -> channel
  digestmap_t* chns_transition;   // pid -> channsl

} mt_cpay_t;

// private initializer functions
static int init_chn_end_setup(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);
static int init_chn_end_estab1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);
static int init_nan_cli_setup1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);
static int init_nan_cli_estab1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);
static int init_nan_cli_pay1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);
static int init_nan_cli_destab1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);
static int init_nan_cli_dpay1(mt_user_notify_t notify, mt_channel_t* chn,  mt_desc_t* desc);
static int init_nan_cli_reqclose1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);
static int init_nan_end_close1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc);

// private handler functions
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_setup2(mt_desc_t* desc, nan_int_setup2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_setup4(mt_desc_t* desc, nan_int_setup4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_setup6(mt_desc_t* desc, nan_int_setup6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab6(mt_desc_t* desc, nan_rel_estab6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_pay2(mt_desc_t* desc, nan_rel_pay2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_destab2(mt_desc_t* desc, nan_int_destab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_dpay2(mt_desc_t* desc, nan_int_dpay2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_reqclose2(mt_desc_t* desc, nan_rel_reqclose2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]);

// private helper functions
static int compare_chn_end_data(const void** a, const void** b);

static workqueue_reply_t wallet_make(void* thread, void* arg);
static void wallet_reply(void* arg);

static int mt_pay_notify(mt_desc_t* desc);
static int mt_directpay_notify(mt_desc_t* desc);
static int mt_close_notify(mt_desc_t* desc);

static mt_cpay_t client;

int mt_cpay_init(void){

  // TODO: get this to workx
  // cpu_init();

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  mt_desc_t ledger;
  int fee;

  /********************************************************************/
  //TODO replace with torrc

  FILE* fp;

  fp = fopen("mt_config_temp/pp", "rb");
  tor_assert(fread(pp, 1, MT_SZ_PP, fp) == MT_SZ_PP);
  fclose(fp);

  fp = fopen("mt_config_temp/cli_pk", "rb");
  tor_assert(fread(pk, 1, MT_SZ_PK, fp) == MT_SZ_PK);
  fclose(fp);

  fp = fopen("mt_config_temp/cli_sk", "rb");
  tor_assert(fread(sk, 1, MT_SZ_SK, fp) == MT_SZ_SK);
  fclose(fp);

  fp = fopen("mt_config_temp/led_desc", "rb");
  tor_assert(fread(&ledger, 1, sizeof(mt_desc_t), fp) == sizeof(mt_desc_t));
  fclose(fp);

  fp = fopen("mt_config_temp/fee", "rb");
  tor_assert(fread(&fee, 1, sizeof(fee), fp) == sizeof(fee));
  fclose(fp);

  /********************************************************************/

  // copy in values crypto fields
  memcpy(client.pp, pp, MT_SZ_PP);
  memcpy(client.pk, pk, MT_SZ_PK);
  memcpy(client.sk, sk, MT_SZ_SK);
  client.ledger = ledger;
  client.fee = fee;

  // initialize channel containers
  client.chns_setup = smartlist_new();
  client.chns_estab = smartlist_new();
  client.nans_setup = smartlist_new();
  client.nans_estab = digestmap_new();
  client.nans_reqclosed = digestmap_new();
  client.chns_transition = digestmap_new();

  // TODO generate new channels
  return MT_SUCCESS;
}

int mt_cpay_pay(mt_desc_t* desc){

  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  // TODO: if out of payments then close channel

  if((chn = digestmap_get(client.nans_estab, (char*)digest)) != NULL)
    return init_nan_cli_pay1(mt_cpay_pay, chn, desc);

  if((chn = smartlist_pop_last(client.nans_setup)) != NULL)
    return init_nan_cli_estab1(mt_cpay_pay, chn, desc);

  if((chn = smartlist_pop_last(client.chns_estab)) != NULL)
    return init_nan_cli_setup1(mt_cpay_pay, chn, desc);

  if((chn = smartlist_pop_last(client.chns_setup)) != NULL)
    return init_chn_end_estab1(mt_cpay_pay, chn, desc);

  return init_chn_end_setup(mt_cpay_pay, NULL, desc);
}

int mt_cpay_directpay(mt_desc_t* desc){

  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  if(((chn = digestmap_get(client.nans_estab, (char*)digest)) != NULL) &&
     chn->data.nan_state.num_payments < chn->data.nan_token.num_payments)
    return init_nan_cli_dpay1(mt_directpay_notify, chn, desc);

  if(((chn = digestmap_get(client.nans_estab, (char*)digest)) != NULL) &&
     chn->data.nan_state.num_payments == chn->data.nan_token.num_payments)
    return init_nan_end_close1(mt_cpay_directpay, chn, desc);

  if((chn = smartlist_pop_last(client.nans_setup)) != NULL)
    return init_nan_cli_destab1(mt_cpay_directpay, chn, desc);

  if((chn = smartlist_pop_last(client.chns_estab)) != NULL)
    return init_nan_cli_setup1(mt_cpay_directpay, chn, desc);

  if((chn = smartlist_pop_last(client.chns_setup)) != NULL)
    return init_chn_end_estab1(mt_cpay_directpay, chn, desc);

  return init_chn_end_setup(mt_cpay_directpay, NULL, desc);
}

int mt_cpay_close(mt_desc_t* desc){

  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  if((chn = digestmap_remove(client.nans_reqclosed, (char*)digest)) != NULL)
    return init_nan_end_close1(mt_close_notify, chn, desc);

  if((chn = digestmap_remove(client.nans_estab, (char*)digest)) != NULL)
    return init_nan_cli_reqclose1(mt_cpay_close, chn, desc);

  log_debug(LD_MT, "descriptor is in an incorrect state to perform the requested action");
  return MT_ERROR;
}

int mt_cpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size){

  int result;
  byte pid[DIGEST_LEN];

  switch(type){
    case MT_NTYPE_ANY_LED_CONFIRM:;
      any_led_confirm_t any_led_confirm_tkn;
      if(unpack_any_led_confirm(msg, size, &any_led_confirm_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_any_led_confirm(desc, &any_led_confirm_tkn, &pid);
      break;
    case MT_NTYPE_CHN_INT_ESTAB2:;
      chn_int_estab2_t chn_int_estab2_tkn;
      if(unpack_chn_int_estab2(msg, size, &chn_int_estab2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab2(desc, &chn_int_estab2_tkn, &pid);
      break;

    case MT_NTYPE_CHN_INT_ESTAB4:;
      chn_int_estab4_t chn_int_estab4_tkn;
      if(unpack_chn_int_estab4(msg, size, &chn_int_estab4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab4(desc, &chn_int_estab4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_SETUP2:;
      nan_int_setup2_t nan_int_setup2_tkn;
      if(unpack_nan_int_setup2(msg, size, &nan_int_setup2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup2(desc, &nan_int_setup2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_SETUP4:;
      nan_int_setup4_t nan_int_setup4_tkn;
      if(unpack_nan_int_setup4(msg, size, &nan_int_setup4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup4(desc, &nan_int_setup4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_SETUP6:;
      nan_int_setup6_t nan_int_setup6_tkn;
      if(unpack_nan_int_setup6(msg, size, &nan_int_setup6_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup6(desc, &nan_int_setup6_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_ESTAB6:;
      nan_rel_estab6_t nan_rel_estab6_tkn;
      if(unpack_nan_rel_estab6(msg, size, &nan_rel_estab6_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_estab6(desc, &nan_rel_estab6_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_PAY2:;
      nan_rel_pay2_t nan_rel_pay2_tkn;
      if(unpack_nan_rel_pay2(msg, size, &nan_rel_pay2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_pay2(desc, &nan_rel_pay2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_DESTAB2:;
      nan_int_destab2_t nan_int_destab2_tkn;
      if(unpack_nan_int_destab2(msg, size, &nan_int_destab2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_destab2(desc, &nan_int_destab2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_DPAY2:;
      nan_int_dpay2_t nan_int_dpay2_tkn;
      if(unpack_nan_int_dpay2(msg, size, &nan_int_dpay2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_dpay2(desc, &nan_int_dpay2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_REQCLOSE2:;
      nan_rel_reqclose2_t nan_rel_reqclose2_tkn;
      if(unpack_nan_rel_reqclose2(msg, size, &nan_rel_reqclose2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_reqclose2(desc, &nan_rel_reqclose2_tkn,  &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE2:;
      nan_int_close2_t nan_int_close2_tkn;
      if(unpack_nan_int_close2(msg, size, &nan_int_close2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close2(desc, &nan_int_close2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE4:;
      nan_int_close4_t nan_int_close4_tkn;
      if(unpack_nan_int_close4(msg, size, &nan_int_close4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close4(desc, &nan_int_close4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE6:;
      nan_int_close6_t nan_int_close6_tkn;
      if(unpack_nan_int_close6(msg, size, &nan_int_close6_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close6(desc, &nan_int_close6_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE8:;
      nan_int_close8_t nan_int_close8_tkn;
      if(unpack_nan_int_close8(msg, size, &nan_int_close8_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close8(desc, &nan_int_close8_tkn, &pid);
      break;

    default:
      result = MT_ERROR;
      break;
  }

  return result;
}

/******************************* Channel Setup **************************/

static int init_chn_end_setup(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  mt_desc_t intermediary;
  if(mt_new_intermediary(&intermediary) != MT_SUCCESS)
    return MT_ERROR;

  // initialize new channel
  chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(&chn->rdesc, desc, sizeof(mt_desc_t));
  memcpy(&chn->idesc, &intermediary, sizeof(mt_desc_t));
  memcpy(chn->data.pk, client.pk, MT_SZ_PK);
  memcpy(chn->data.sk, client.sk, MT_SZ_SK);
  mt_crypt_rand(MT_SZ_ADDR, chn->data.addr);

  chn->callback = notify;
  memcpy(&(chn->callback_desc), desc, sizeof(mt_desc_t));

  // TODO finish initializing channel

  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);

  // initialize setup token
  chn_end_setup_t token;
  token.val_from = 50 + client.fee;
  token.val_to = 50;
  memcpy(token.from, client.addr, MT_SZ_ADDR);
  memcpy(token.chn, chn->data.addr, MT_SZ_ADDR);
  // skip chn_token for now

  // send setup message
  byte* packed_msg;
  byte* signed_msg;
  int packed_msg_size = pack_chn_end_setup(&token, &pid, &packed_msg);
  int signed_msg_size = mt_create_signed_msg(packed_msg, packed_msg_size,
					     &chn->data.pk, &chn->data.sk, &signed_msg);
  return mt_send_message(&client.ledger, MT_NTYPE_CHN_END_SETUP, signed_msg, signed_msg_size);
}

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message

  digestmap_remove(client.chns_transition, (char*)*pid);
  smartlist_add(client.chns_setup, chn);

  if(chn->callback != NULL)
    return chn->callback(&chn->callback_desc);
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int init_chn_end_estab1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;
  chn->callback_desc = *desc;

  // intiate token in workerqueue

  chn_end_estab1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_chn_end_estab1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(&chn->idesc, MT_NTYPE_CHN_END_ESTAB1, msg, msg_size);

  return MT_SUCCESS;
}

static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  chn_end_estab3_t reply;

  // fill reply with correct values

  byte* reply_msg;
  int reply_size = pack_chn_end_estab3(&reply, pid, &reply_msg);
  mt_send_message(desc, MT_NTYPE_CHN_END_ESTAB3, reply_msg, reply_size);
  return MT_SUCCESS;
}

static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  digestmap_remove(client.chns_transition, (char*)*pid);
  smartlist_add(client.chns_estab, chn);

  // check validity of incoming message
  if(chn->callback != NULL)
    chn->callback(&chn->callback_desc);
  return MT_SUCCESS;
}

/******************************** Nano Setup ****************************/

static int init_nan_cli_setup1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;
  chn->callback_desc = *desc;

  // intiate token
  nan_cli_setup1_t token;

  // intiate token in workerqueue

  // need to figure out this zkp generating business
  /* // if we have not started making the token then start making it */
  /* if(chn->zkp_state == MT_ZKP_STATE_NONE){ */
  /*   mt_desc_t* arg = malloc(sizeof(mt_desc_t)); */
  /*   memcpy(arg, desc, sizeof(mt_desc_t)); */

  /*   // fn is going to call commit wallet */
  /*   // reply_fn is going to call notify */
  /*   printf("got here\n"); */
  /*   workqueue_entry_t* entry = cpuworker_queue_work(WQ_PRI_HIGH, wallet_make, wallet_reply, arg); */
  /*   printf("but not here\n"); */
  /*   if(entry == NULL) */
  /*     return MT_ERROR; */
  /*   return MT_SUCCESS; */
  /* } */

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_setup1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(&chn->idesc, MT_NTYPE_NAN_CLI_SETUP1, msg, msg_size);

  return MT_SUCCESS;
}

static int handle_nan_int_setup2(mt_desc_t* desc, nan_int_setup2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  nan_cli_setup3_t reply;

  // fill reply with correct values

  byte* reply_msg;
  int reply_size = pack_nan_cli_setup3(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_CLI_SETUP3, reply_msg, reply_size);
}

static int handle_nan_int_setup4(mt_desc_t* desc, nan_int_setup4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  nan_cli_setup5_t reply;

  // fill reply with correct values

  byte* reply_msg;
  int reply_size = pack_nan_cli_setup5(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_CLI_SETUP5, reply_msg, reply_size);
}

static int handle_nan_int_setup6(mt_desc_t* desc, nan_int_setup6_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  digestmap_remove(client.chns_transition, (char*)*pid);
  smartlist_add(client.nans_setup, chn);

  // sort nans_setup here?

  // check validity incoming message
  if(chn->callback != NULL)
    chn->callback(&chn->callback_desc);
  return MT_SUCCESS;
}

/**************************** Nano Establish ****************************/

static int init_nan_cli_estab1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;
  // intiate token
  nan_cli_estab1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_estab1(&token, &pid, &msg);
  return mt_send_message_multidesc(desc, &chn->idesc, MT_NTYPE_NAN_CLI_ESTAB1, msg, msg_size);
}

static int handle_nan_rel_estab6(mt_desc_t* desc, nan_rel_estab6_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_estab, (char*)digest, chn);

  if(chn->callback != NULL){
    chn->callback(&chn->callback_desc);
  }
  return MT_SUCCESS;
}

/******************************* Nano Pay *******************************/

static int init_nan_cli_pay1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;

  // intiate token

  nan_cli_pay1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_pay1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  return mt_send_message(desc, MT_NTYPE_NAN_CLI_PAY1, msg, msg_size);
}

static int handle_nan_rel_pay2(mt_desc_t* desc, nan_rel_pay2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_estab, (char*)desc, chn);
  return MT_SUCCESS;
}

/************************ Nano Direct Establish *************************/

static int init_nan_cli_destab1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;
  // intiate token
  nan_cli_destab1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_destab1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(desc, MT_NTYPE_NAN_CLI_DESTAB1, msg, msg_size);

  return MT_SUCCESS;
}

static int handle_nan_int_destab2(mt_desc_t* desc, nan_int_destab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_estab, (char*)desc, chn);

  // check validity incoming message
  if(chn->callback != NULL)
    chn->callback(&chn->callback_desc);
  return MT_SUCCESS;

  // check validity incoming message
  if(chn->callback != NULL)
    chn->callback(&chn->callback_desc);
  return MT_SUCCESS;
}

/**************************** Nano Direct Pay ***************************/

static int init_nan_cli_dpay1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;
  // intiate token
  nan_cli_dpay1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_dpay1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(desc, MT_NTYPE_NAN_CLI_DPAY1, msg, msg_size);

  return MT_SUCCESS;
}

static int handle_nan_int_dpay2(mt_desc_t* desc, nan_int_dpay2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_estab, (char*)desc, chn);

  // check validity incoming message
  if(chn->callback != NULL)
    chn->callback(&chn->callback_desc);
  return MT_SUCCESS;
}

/****************************** Nano Req Close **************************/

static int init_nan_cli_reqclose1(mt_user_notify_t notify, mt_channel_t* chn,  mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;
  chn->callback_desc = *desc;

  // intiate token
  nan_cli_reqclose1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_reqclose1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(desc, MT_NTYPE_NAN_CLI_REQCLOSE1, msg, msg_size);

  return MT_SUCCESS;
}

static int handle_nan_rel_reqclose2(mt_desc_t* desc, nan_rel_reqclose2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_reqclosed, (char*)desc, chn);

  // check validity incoming message
  if(chn->callback != NULL)
    chn->callback(&chn->callback_desc);
  return MT_SUCCESS;
}

/******************************* Nano Close *****************************/

static int init_nan_end_close1(mt_user_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->callback = notify;
  // intiate token
  nan_end_close1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_nan_end_close1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE1, msg, msg_size);

  return MT_SUCCESS;
}

static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  nan_end_close3_t reply;

  // fill reply with correct values

  byte* reply_msg;
  int reply_size = pack_nan_end_close3(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE3, reply_msg, reply_size);
}

static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  nan_end_close5_t reply;

  // fill reply with correct values

  byte* reply_msg;
  int reply_size = pack_nan_end_close5(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE5, reply_msg, reply_size);
}

static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  nan_end_close7_t reply;

  // fill reply with correct values

  byte* reply_msg;
  int reply_size = pack_nan_end_close7(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE7, reply_msg, reply_size);
}

static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_estab, (char*)desc, chn);

  if(chn->callback != NULL)
    chn->callback(&chn->callback_desc);
  return MT_SUCCESS;
}

/***************************** Helper Functions *************************/

static int compare_chn_end_data(const void** a, const void** b){

  if(((mt_channel_t*)(*a))->data.balance > ((mt_channel_t*)(*b))->data.balance)
    return -1;

  if(((mt_channel_t*)(*a))->data.balance < ((mt_channel_t*)(*b))->data.balance)
    return 1;

  return MT_SUCCESS;
}

static workqueue_reply_t wallet_make(void* thread, void* arg){
  //unpack wallet to components and call make wallet
  (void)thread;
  (void)arg;

  workqueue_reply_t reply = WQ_RPL_REPLY;
  return reply;
}

static void wallet_reply(void* arg){
  (void)arg;
  //extract callback from arg and call it
}

static int mt_pay_notify(mt_desc_t* desc){
  (void)desc;
  return 0;
}

static int mt_directpay_notify(mt_desc_t* desc){
  (void)desc;
  return 0;

}

static int mt_close_notify(mt_desc_t* desc){
  (void)desc;

  smartlist_sort(client.nans_setup, compare_chn_end_data);
  return 0;
}
