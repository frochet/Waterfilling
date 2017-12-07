#pragma GCC diagnostic ignored "-Wswitch-enum"

//TODO figure out callback business for handlers
//    probably should make callbacks more general with dynamic arg list

#include<pthread.h>

#include "or.h"
#include "cpuworker.h"
#include "workqueue.h"
#include "mt_common.h"
#include "mt_rpay.h"

typedef void (*work_task)(void*);

typedef struct {
  int (*fn)(mt_desc_t*, mt_ntype_t, byte*, int);
  mt_desc_t dref1;
  mt_ntype_t arg2;
  byte* arg3;
  int arg4;
} mt_callback_t;

typedef struct {
  mt_desc_t cdesc;
  mt_desc_t idesc;
  chn_end_data_t data;

  mt_callback_t callback;
} mt_channel_t;

typedef struct {
  mt_channel_t* chn;
  byte pid[DIGEST_LEN];
} mt_wcom_args_t;

/**
 * Single instance of a relay payment object
 */
typedef struct {

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte addr[MT_SZ_ADDR];
  mt_desc_t ledger;
  int fee;

  digestmap_t* chns_setup;       // int desc -> smartlist of channels
  digestmap_t* chns_estab;       // int desc -> smartlist of channels
  digestmap_t* nans_estab;       // cli desc -> channel
  digestmap_t* chns_transition;  // pid -> channel

  digestmap_t* clis_intermediary; // cli desc -> int desc
} mt_rpay_t;

static mt_rpay_t relay;

// initializer functions
static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_end_close1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);

// local handler functions
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_estab1(mt_desc_t* desc, nan_cli_estab1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_estab3(mt_desc_t* desc, nan_int_estab3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_pay1(mt_desc_t* desc, nan_cli_pay1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_reqclose1(mt_desc_t* desc, nan_cli_reqclose1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]);

// helper functions
static int help_chn_end_estab1(void* args);
static int help_chn_int_estab4(void* args);
static int help_nan_int_close8(void *args);

static workqueue_reply_t wcom_task(void* thread, void* arg);

static mt_channel_t* new_channel(void);
static void digestmap_smartlist_append(digestmap_t* map, char* key, void* val);
static void* digestmap_smartlist_pop_last(digestmap_t* map, char* key);

// Tor-facing API
int mt_rpay_init(void){

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

  fp = fopen("mt_config_temp/rel_pk", "rb");
  tor_assert(fread(pk, 1, MT_SZ_PK, fp) == MT_SZ_PK);
  fclose(fp);

  fp = fopen("mt_config_temp/rel_sk", "rb");
  tor_assert(fread(sk, 1, MT_SZ_SK, fp) == MT_SZ_SK);
  fclose(fp);

  fp = fopen("mt_config_temp/led_desc", "rb");
  tor_assert(fread(&ledger, 1, sizeof(mt_desc_t), fp) == sizeof(mt_desc_t));
  fclose(fp);

  fp = fopen("mt_config_temp/fee", "rb");
  tor_assert(fread(&fee, 1, sizeof(fee), fp) == sizeof(fee));
  fclose(fp);

  /********************************************************************/

  // copy macro-level crypto fields
  memcpy(relay.pp, pp, MT_SZ_PP);
  memcpy(relay.pk, pk, MT_SZ_PK);
  memcpy(relay.sk, sk, MT_SZ_SK);
  relay.ledger = ledger;
  relay.fee = fee;

  // initiate containers
  relay.chns_setup = digestmap_new();
  relay.chns_estab = digestmap_new();
  relay.nans_estab = digestmap_new();
  relay.chns_transition = digestmap_new();
  relay.clis_intermediary = digestmap_new();

  return MT_SUCCESS;
}

int mt_rpay_recv_multidesc(mt_desc_t* client, mt_desc_t* intermediary, mt_ntype_t type, byte* msg, int size){
  (void)intermediary;

  byte digest[DIGEST_LEN];
  mt_desc2digest(client, &digest);
  mt_desc_t* int_desc = tor_malloc(sizeof(mt_desc_t));
  memcpy(int_desc, intermediary, sizeof(mt_desc_t));

  digestmap_set(relay.clis_intermediary, (char*)digest, int_desc);
  return mt_rpay_recv(client, type, msg, size);
}

int mt_rpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size){

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

    case MT_NTYPE_NAN_CLI_ESTAB1:;
      nan_cli_estab1_t nan_cli_estab1_tkn;
      if(unpack_nan_cli_estab1(msg, size, &nan_cli_estab1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_estab1(desc, &nan_cli_estab1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_ESTAB3:;
      nan_int_estab3_t nan_int_estab3_tkn;
      if(unpack_nan_int_estab3(msg, size, &nan_int_estab3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_estab3(desc, &nan_int_estab3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_ESTAB5:;
      nan_int_estab5_t nan_int_estab5_tkn;
      if(unpack_nan_int_estab5(msg, size, &nan_int_estab5_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_estab5(desc, &nan_int_estab5_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_PAY1:;
      nan_cli_pay1_t nan_cli_pay1_tkn;
      if(unpack_nan_cli_pay1(msg, size, &nan_cli_pay1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_pay1(desc, &nan_cli_pay1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_REQCLOSE1:;
      nan_cli_reqclose1_t nan_cli_reqclose1_tkn;
      if(unpack_nan_cli_reqclose1(msg, size, &nan_cli_reqclose1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_reqclose1(desc, &nan_cli_reqclose1_tkn, &pid);
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
  }
  return result;
}

/******************************* Channel Escrow *************************/

static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // TODO finish initializing channel

  // initialize setup token
  chn_end_setup_t token;
  token.val_from = 50 + relay.fee;
  token.val_to = 50;
  memcpy(token.from, relay.addr, MT_SZ_ADDR);
  memcpy(token.chn, chn->data.addr, MT_SZ_ADDR);
  // skip chn_token for now

  // send setup message
  byte* packed_msg;
  byte* signed_msg;
  int packed_msg_size = pack_chn_end_setup(&token, pid, &packed_msg);
  int signed_msg_size = mt_create_signed_msg(packed_msg, packed_msg_size,
					     &chn->data.pk, &chn->data.sk, &signed_msg);

  return mt_send_message(&relay.ledger, MT_NTYPE_CHN_END_SETUP, signed_msg, signed_msg_size);
}

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message
  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->idesc, &digest);
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_smartlist_append(relay.chns_setup, (char*)digest, chn);


  if(chn->callback.fn){
    mt_callback_t cb = chn->callback;
    return cb.fn(&cb.dref1, cb.arg2, cb.arg3, cb.arg4);
  }
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  mt_wcom_args_t* args = tor_malloc(sizeof(mt_wcom_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  if(!cpuworker_queue_work(WQ_PRI_HIGH, wcom_task, (work_task)help_chn_end_estab1, args))
    return MT_ERROR;
  return MT_SUCCESS;

}

static int help_chn_end_estab1(void* args){

  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_wcom_args_t*)args)->pid, DIGEST_LEN);
  free(args);

  chn_end_estab1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_chn_end_estab1(&token, &pid, &msg);
  return mt_send_message(&chn->idesc, MT_NTYPE_CHN_END_ESTAB1, msg, msg_size);
}

static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  chn_end_estab3_t reply;

  // fill reply with correct values;

  byte* reply_msg;
  int reply_size = pack_chn_end_estab3(&reply, pid, &reply_msg);
  mt_send_message(desc, MT_NTYPE_CHN_END_ESTAB3, reply_msg, reply_size);

  return MT_SUCCESS;
}

static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  // prepare nanopayment channel token now
  mt_wcom_args_t* args = tor_malloc(sizeof(mt_wcom_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  if(!cpuworker_queue_work(WQ_PRI_HIGH, wcom_task, (work_task)help_chn_int_estab4, args))
    return MT_ERROR;
  return MT_SUCCESS;
}

static int help_chn_int_estab4(void* args){

  // extract parameters
  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_wcom_args_t*)args)->pid, DIGEST_LEN);
  free(args);

  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->idesc, &digest);
  digestmap_remove(relay.chns_transition, (char*)pid);
  digestmap_smartlist_append(relay.chns_estab, (char*)digest, chn);

  if(chn->callback.fn){
    mt_callback_t cb = chn->callback;
    return cb.fn(&cb.dref1, cb.arg2, cb.arg3, cb.arg4);
  }
  return MT_SUCCESS;
}


/****************************** Nano Establish **************************/

static int handle_nan_cli_estab1(mt_desc_t* desc, nan_cli_estab1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  mt_channel_t* chn;
  byte rdigest[DIGEST_LEN];
  mt_desc2digest(desc, &rdigest);

  mt_desc_t* intermediary = digestmap_get(relay.clis_intermediary, (char*)rdigest);
  byte idigest[DIGEST_LEN];
  mt_desc2digest(intermediary, &idigest);

  // we have a free channel with this intermediary
  if((chn = digestmap_smartlist_pop_last(relay.chns_estab, (char*)idigest))){
    digestmap_set(relay.chns_transition, (char*)*pid, chn);
    chn->cdesc = *desc;
    chn->callback.fn = NULL;

    // ZKP

    //************************************************************//
    // Wrap this in helper that gets called afterwards
    nan_rel_estab2_t reply;

    // send message
    byte* reply_msg;
    int reply_size = pack_nan_rel_estab2(&reply, pid, &reply_msg);
    return mt_send_message(&chn->idesc, MT_NTYPE_NAN_REL_ESTAB2, reply_msg, reply_size);
    //************************************************************//
  }

  byte rpid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, rpid);

  // if we have a channel setup then establish it
  if((chn = digestmap_smartlist_pop_last(relay.chns_setup, (char*)idigest))){
    digestmap_set(relay.chns_transition, (char*)rpid, chn);
    chn->callback = (mt_callback_t){.fn = mt_rpay_recv, .dref1 = *desc, .arg2 = MT_NTYPE_NAN_CLI_ESTAB1};
    chn->callback.arg4 = pack_nan_cli_estab1(token, pid, &chn->callback.arg3);
    return init_chn_end_estab1(chn, &rpid);
  }

  // setup a new channel with the intermediary
  chn = new_channel();
  digestmap_set(relay.chns_transition, (char*)rpid, chn);
  chn->idesc = *intermediary;
  chn->callback = (mt_callback_t){.fn = mt_rpay_recv, .dref1 = *desc, .arg2 = MT_NTYPE_NAN_CLI_ESTAB1};
  chn->callback.arg4 = pack_nan_cli_estab1(token, pid, &chn->callback.arg3);
  return init_chn_end_setup(chn, &rpid);
}



static int handle_nan_int_estab3(mt_desc_t* desc, nan_int_estab3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_rel_estab4_t reply;

  // fill reply with correct values;

  byte* reply_msg;
  int reply_size = pack_nan_rel_estab4(&reply, pid, &reply_msg);
  mt_send_message(desc, MT_NTYPE_NAN_REL_ESTAB4, reply_msg, reply_size);

  return MT_SUCCESS;
}

static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->cdesc, &digest);
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_set(relay.nans_estab, (char*)digest, chn);

  nan_rel_estab6_t reply;

  // fill reply with correct values;

  byte* reply_msg;
  int reply_size = pack_nan_rel_estab6(&reply, pid, &reply_msg);
  return mt_send_message(&chn->cdesc, MT_NTYPE_NAN_REL_ESTAB6, reply_msg, reply_size);
}

/******************************* Nano Pay *******************************/

static int handle_nan_cli_pay1(mt_desc_t* desc, nan_cli_pay1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  nan_rel_pay2_t reply;

  // fill reply with correct values;

  mt_alert_payment(desc);

  byte* reply_msg;
  int reply_size = pack_nan_rel_pay2(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_REL_PAY2, reply_msg, reply_size);
}

/*************************** Nano Req Close *****************************/

static int handle_nan_cli_reqclose1(mt_desc_t* desc, nan_cli_reqclose1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);


  if((chn = digestmap_remove(relay.nans_estab, (char*)digest)) != NULL){
    digestmap_set(relay.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = mt_rpay_recv, .dref1 = *desc};
    chn->callback.arg2 = MT_NTYPE_NAN_CLI_REQCLOSE1;
    chn->callback.arg4 = pack_nan_cli_reqclose1(token, pid, &chn->callback.arg3);
    return init_nan_end_close1(chn, pid);
  }

  nan_rel_reqclose2_t reply;

  // fill reply with correct values;

  byte* reply_msg;
  int reply_size = pack_nan_rel_reqclose2(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_REL_REQCLOSE2, reply_msg, reply_size);
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

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close3_t reply;

  // fill reply with correct values;

  byte* reply_msg;
  int reply_size = pack_nan_end_close3(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE3, reply_msg, reply_size);
}

static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close5_t reply;

  // fill reply with correct values;

  byte* reply_msg;
  int reply_size = pack_nan_end_close5(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE5, reply_msg, reply_size);
}

static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close7_t reply;

  // fill reply with correct values;

  byte* reply_msg;
  int reply_size = pack_nan_end_close7(&reply, pid, &reply_msg);
  return mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE7, reply_msg, reply_size);
}

static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;


  mt_wcom_args_t* args = tor_malloc(sizeof(mt_wcom_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  if(!cpuworker_queue_work(WQ_PRI_HIGH, wcom_task, (work_task)help_nan_int_close8, args))
    return MT_ERROR;
  return MT_SUCCESS;

}

static int help_nan_int_close8(void *args){
  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_wcom_args_t*)args)->pid, DIGEST_LEN);
  free(args);

  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->idesc, &digest);
  digestmap_remove(relay.chns_transition, (char*)pid);
  digestmap_set(relay.nans_estab, (char*)digest, chn);

  if(chn->callback.fn){
    mt_callback_t cb = chn->callback;
    return cb.fn(&cb.dref1, cb.arg2, cb.arg3, cb.arg4);
  }
  return MT_SUCCESS;
}

/*************************** Helper Functions ***************************/

static mt_channel_t* new_channel(void){
  // initialize new channel
  mt_channel_t* chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(chn->data.pk, relay.pk, MT_SZ_PK);
  memcpy(chn->data.sk, relay.sk, MT_SZ_SK);
  mt_crypt_rand(MT_SZ_ADDR, chn->data.addr);
  return chn;
}
/**
 * Append a value to the appropriate list in a digestmap of smartlists
 */
static void digestmap_smartlist_append(digestmap_t* map, char* key, void* val){
  smartlist_t* list = digestmap_get(map, (char*)key);
  if(list == NULL){
    digestmap_set(map, (char*)key, smartlist_new());
    list = digestmap_get(map, (char*)key);
  }
  smartlist_add(list, val);
}

/**
 * Pop the last item from the appropriate list in a digestmap of smartlists
 */
static void* digestmap_smartlist_pop_last(digestmap_t* map, char* key){
  smartlist_t* list = digestmap_get(map, (char*)key);
  if(!list)
    return NULL;
  return smartlist_pop_last(list);
}

static workqueue_reply_t wcom_task(void* thread, void* args){
  (void)thread;

  // extract parameters
  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  (void)chn;

  // call mt_commit_wallet here
  return WQ_RPL_REPLY;
}
