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

typedef struct {
  // callback function
  int (*fn)(mt_desc_t*, mt_desc_t*);

  // args
  mt_desc_t dref1;
  mt_desc_t dref2;
} mt_callback_t;

typedef enum {
  MT_ZKP_STATE_NONE,
  MT_ZKP_STATE_STARTED,
  MT_ZKP_STATE_READY,
} mt_zkp_state_t;

typedef struct {
  mt_desc_t rdesc;
  mt_desc_t idesc;
  chn_end_data_t data;

  mt_zkp_state_t zkp_state;
  mt_callback_t callback;
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
  digestmap_t* nans_destab;        // desc -> channel
  digestmap_t* nans_reqclosed;    // desc -> channel
  digestmap_t* chns_transition;   // pid -> channel
} mt_cpay_t;

// private initializer functions
static mt_channel_t* new_channel(void);
static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_setup1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_pay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_destab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_dpay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_reqclose1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_end_close1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);

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

// helper functions that are called after workqueued zkp proof is generated
static int help_chn_end_estab1(void* args);
static int help_nan_cli_setup1(void* args);
static int help_nan_int_close8(void* args);

// private helper functions
static int compare_chn_end_data(const void** a, const void** b);
static mt_channel_t* smartlist_search_idesc(smartlist_t* list, mt_desc_t* desc);

static workqueue_reply_t wallet_make(void* thread, void* arg);
static void wallet_reply(void* arg);

static int mt_pay_notify(mt_desc_t* rdesc, mt_desc_t* idesc);
static int mt_close_notify(mt_desc_t* rdesc, mt_desc_t* idesc);

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
  client.nans_destab = digestmap_new();
  client.nans_reqclosed = digestmap_new();
  client.chns_transition = digestmap_new();

  // TODO generate new channels
  return MT_SUCCESS;
}

int mt_cpay_pay(mt_desc_t* rdesc, mt_desc_t* idesc){

  mt_channel_t* chn;

  byte digest[DIGEST_LEN];
  mt_desc2digest(rdesc, &digest);

  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);

  // TODO: if out of payments then close channel

  // intermediary payment
  if(rdesc->id != idesc->id){
    // make payment if possible
    if((chn = digestmap_remove(client.nans_estab, (char*)digest)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->callback = (mt_callback_t){.fn = mt_pay_notify, .dref1 = *rdesc, .dref2 = *idesc};
      return init_nan_cli_pay1(chn, &pid);
    }

    // establish nanopayment channel if possible
    if((chn = smartlist_pop_last(client.nans_setup)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->rdesc = *rdesc;
      chn->callback = (mt_callback_t){.fn = mt_cpay_pay, .dref1 = *rdesc, .dref2 = *idesc};
      return init_nan_cli_estab1(chn, &pid);
    }

    // setup nanopayment channel if possible
    if((chn = smartlist_pop_last(client.chns_estab)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->callback = (mt_callback_t){.fn = mt_cpay_pay, .dref1 = *rdesc, .dref2 = *idesc};
      return init_nan_cli_setup1(chn, &pid);
    }

    // establish channel if possible
    if((chn = smartlist_pop_last(client.chns_setup)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->callback = (mt_callback_t){.fn = mt_cpay_pay, .dref1 = *rdesc, .dref2 = *idesc};
      return init_chn_end_estab1(chn, &pid);
    }
  }
  // direct payment
  else {
    if((chn = digestmap_remove(client.nans_destab, (char*)digest)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->callback = (mt_callback_t){.fn = mt_pay_notify, .dref1 = *rdesc, .dref2 = *idesc};
      return init_nan_cli_dpay1(chn, &pid);
    }

    if((chn = smartlist_search_idesc(client.nans_setup, rdesc)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->rdesc = *rdesc;
      chn->callback = (mt_callback_t){.fn = mt_cpay_pay, .dref1 = *rdesc, .dref2 = *idesc};
      return init_nan_cli_destab1(chn, &pid);
    }

    if((chn = smartlist_search_idesc(client.chns_estab, rdesc)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->callback = (mt_callback_t){.fn = mt_cpay_pay, .dref1 = *rdesc, .dref2 = *idesc};
      return init_nan_cli_setup1(chn, &pid);
    }

    if((chn = smartlist_search_idesc(client.chns_setup, rdesc)) != NULL){
      digestmap_set(client.chns_transition, (char*)pid, chn);
      chn->callback = (mt_callback_t){.fn = mt_cpay_pay, .dref1 = *rdesc, .dref2 = *idesc};
      return init_chn_end_estab1(chn, &pid);
    }
  }

  // setup channel
  chn = new_channel();
  digestmap_set(client.chns_transition, (char*)pid, chn);
  chn->idesc = *idesc;
  chn->callback = (mt_callback_t){.fn = mt_cpay_pay, .dref1 = *rdesc};
  return init_chn_end_setup(chn, &pid);
}

int mt_cpay_close(mt_desc_t* rdesc, mt_desc_t* idesc){
  mt_channel_t* chn;

  byte digest[DIGEST_LEN];
  mt_desc2digest(rdesc, &digest);

  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);

  if((chn = digestmap_remove(client.nans_reqclosed, (char*)digest)) != NULL){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = mt_close_notify, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_end_close1(chn, &pid);
  }

  if((chn = digestmap_remove(client.nans_estab, (char*)digest)) != NULL){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = mt_cpay_close, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_reqclose1(chn, &pid);
  }

  if((chn = digestmap_remove(client.nans_destab, (char*)digest)) != NULL){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = mt_close_notify, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_end_close1(chn, &pid);
  }

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

static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

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
  int packed_msg_size = pack_chn_end_setup(&token, pid, &packed_msg);
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

  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // ZKP

  /****************************************************************/
  // Wrap this in helper that gets called afterwards
  chn_end_estab1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_chn_end_estab1(&token, pid, &msg);
  mt_send_message(&chn->idesc, MT_NTYPE_CHN_END_ESTAB1, msg, msg_size);

  return MT_SUCCESS;
  /****************************************************************/
}

static int help_chn_end_estab1(void* args){
  (void)args;
  // finish chn_end_estab1
  return 0;
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
  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/******************************** Nano Setup ****************************/

static int init_nan_cli_setup1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // intiate token
  nan_cli_setup1_t token;

  /****************************************************************/
  // Wrap this in helper that gets called afterwards

  // ZKP

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
  /****************************************************************/

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_setup1(&token, pid, &msg);
  mt_send_message(&chn->idesc, MT_NTYPE_NAN_CLI_SETUP1, msg, msg_size);

  return MT_SUCCESS;
}

static int help_nan_cli_setup1(void* args){
  (void)args;
  // finish making setup
  return 0;
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
  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/**************************** Nano Establish ****************************/

static int init_nan_cli_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // add new protocol to chns_transition

  // intiate token
  nan_cli_estab1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_estab1(&token, pid, &msg);
  return mt_send_message_multidesc(&chn->rdesc, &chn->idesc, MT_NTYPE_NAN_CLI_ESTAB1, msg, msg_size);
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

  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/******************************* Nano Pay *******************************/

static int init_nan_cli_pay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // intiate token

  nan_cli_pay1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_pay1(&token, pid, &msg);
  return mt_send_message(&chn->rdesc, MT_NTYPE_NAN_CLI_PAY1, msg, msg_size);
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
  digestmap_set(client.nans_estab, (char*)digest, chn);

  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/************************ Nano Direct Establish *************************/

static int init_nan_cli_destab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // intiate token
  nan_cli_destab1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_destab1(&token, pid, &msg);
  return mt_send_message(&chn->idesc, MT_NTYPE_NAN_CLI_DESTAB1, msg, msg_size);
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
  digestmap_set(client.nans_destab, (char*)digest, chn);

  // check validity incoming message

  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/**************************** Nano Direct Pay ***************************/

static int init_nan_cli_dpay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // intiate token
  nan_cli_dpay1_t token;

  // TODO finish making setup;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_dpay1(&token, pid, &msg);
  return mt_send_message(&chn->idesc, MT_NTYPE_NAN_CLI_DPAY1, msg, msg_size);
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
  digestmap_set(client.nans_destab, (char*)digest, chn);

  // check validity incoming message
  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/****************************** Nano Req Close **************************/

static int init_nan_cli_reqclose1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // intiate token
  nan_cli_reqclose1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_reqclose1(&token, pid, &msg);
  return mt_send_message(&chn->rdesc, MT_NTYPE_NAN_CLI_REQCLOSE1, msg, msg_size);
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
  digestmap_set(client.nans_reqclosed, (char*)digest, chn);

  // check validity incoming message
  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/******************************* Nano Close *****************************/

static int init_nan_end_close1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // intiate token
  nan_end_close1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_nan_end_close1(&token, pid, &msg);
  return mt_send_message(&chn->idesc, MT_NTYPE_NAN_END_CLOSE1, msg, msg_size);
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

  /****************************************************************/
  // Wrap this in helper that gets called afterwards
  // ZKP -> callback to nobody?

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity incoming message

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  smartlist_add(client.nans_setup, chn);

  if(chn->callback.fn != NULL)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
  /****************************************************************/
}

static int help_nan_int_close8(void* args){
  (void)args;
  return 0;
}

/***************************** Helper Functions *************************/

static mt_channel_t* new_channel(void){

  // initialize new channel
  mt_channel_t* chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(chn->data.pk, client.pk, MT_SZ_PK);
  memcpy(chn->data.sk, client.sk, MT_SZ_SK);
  mt_crypt_rand(MT_SZ_ADDR, chn->data.addr);

  // TODO finish initializing channel

  return chn;
}

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

static int mt_pay_notify(mt_desc_t* rdesc, mt_desc_t* idesc){
  (void)rdesc;
  (void)idesc;
  return 0;
}

static int mt_directpay_notify(mt_desc_t* rdesc, mt_desc_t* idesc){
  (void)rdesc;
  (void)idesc;
  return MT_SUCCESS;
}

static int mt_close_notify(mt_desc_t* rdesc, mt_desc_t* idesc){
  (void)rdesc;
  (void)idesc;

  //smartlist_sort(client.nans_setup, compare_chn_end_data);
  return MT_SUCCESS;
}

static mt_channel_t* smartlist_search_idesc(smartlist_t* list, mt_desc_t* desc){

  SMARTLIST_FOREACH_BEGIN(list, mt_channel_t*, elm){
    if(elm->idesc.id == desc->id && elm->idesc.party == desc->party)
      return elm;
  } SMARTLIST_FOREACH_END(elm);
  return NULL;
}
