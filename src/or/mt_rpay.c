#pragma GCC diagnostic ignored "-Wswitch-enum"

//TODO figure out callback business for handlers
//    probably should make callbacks more general with dynamic arg list

#include<pthread.h>

#include "or.h"
#include "workqueue.h"
#include "mt_common.h"
#include "mt_rpay.h"

typedef enum {
  MT_ZKP_STATE_NONE,
  MT_ZKP_STATE_STARTED,
  MT_ZKP_STATE_READY,
} mt_zkp_state_t;

typedef struct {
  mt_desc_t* desc;
  mt_ntype_t type;
  byte* msg;
  int size;
} mt_recv_args_t;

typedef struct {
  mt_desc_t cdesc;
  mt_desc_t idesc;
  chn_end_data_t data;

  mt_recv_args_t cb_args;

  mt_zkp_state_t zkp_state;

} mt_channel_t;

/**
 * Single instance of a relay payment object
 */
typedef struct {

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte addr[MT_SZ_ADDR];

  mt_desc_t ledger;

  digestmap_t* chns_setup;       // int desc -> smartlist of channels
  digestmap_t* chns_estab;       // int desc -> smartlist of channels
  digestmap_t* chns_nansetup;    // int desc -> smartlist of channels
  digestmap_t* chns_nanestab;    // cli desc -> smartlist of channels
  digestmap_t* chns_transition;  // pid -> channel
} mt_rpay_t;

static mt_rpay_t relay;

// initializer functions
static int init_chn_end_setup(mt_recv_args_t args, mt_channel_t* chn, mt_desc_t* desc);
static int init_chn_end_estab1(mt_recv_args_t args, mt_channel_t* chn,  mt_desc_t* desc);
static int init_nan_end_close1(mt_recv_args_t args, mt_channel_t* chn, mt_desc_t* desc);

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

// Tor-facing API
int mt_rpay_init(void){

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  mt_desc_t ledger;

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

  /********************************************************************/

  // copy macro-level crypto fields
  memcpy(relay.pp, pp, MT_SZ_PP);
  memcpy(relay.pk, pk, MT_SZ_PK);
  memcpy(relay.sk, sk, MT_SZ_SK);
  relay.ledger = ledger;

  // initiate containers
  relay.chns_setup = digestmap_new();
  relay.chns_estab = digestmap_new();
  relay.chns_nansetup = digestmap_new();
  relay.chns_nanestab = digestmap_new();
  relay.chns_transition = digestmap_new();

  return MT_SUCCESS;
}

int mt_rpay_recv_multidesc(mt_desc_t* client, mt_desc_t* intermediary, mt_ntype_t type, byte* msg, int size){
  (void)intermediary;

  // save mapping between client->intermediary

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

/**************************** Initialize Protocols **********************/

static int init_chn_end_setup(mt_recv_args_t args, mt_channel_t* chn, mt_desc_t* desc){

  mt_desc_t* intermediary = malloc(sizeof(mt_desc_t));
  if(mt_new_intermediary(intermediary) != MT_SUCCESS)
    return MT_ERROR;

  // initialize new channel
  chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(&chn->idesc, intermediary, sizeof(mt_desc_t));
  memcpy(chn->data.pk, relay.pk, MT_SZ_PK);
  memcpy(chn->data.sk, relay.pk, MT_SZ_PK);

  // TODO finish initializing channel

  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(relay.chns_transition, (char*)pid, chn);
  chn->cb_args = args;

  // initialize escrow token
  chn_end_setup_t token;

  // TODO finish making escrow token

  // send escrow message
  byte* msg;
  int msg_size = pack_chn_end_setup(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(desc, MT_NTYPE_CHN_END_SETUP, msg, msg_size);

  return MT_SUCCESS;
}

static int init_chn_end_estab1(mt_recv_args_t args, mt_channel_t* chn,  mt_desc_t* desc){
  // add new protocol to chns_transition
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(relay.chns_transition, (char*)pid, chn);
  chn->cb_args = args;

  // intiate token
  chn_end_estab1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_chn_end_estab1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(desc, MT_NTYPE_CHN_END_ESTAB1, msg, msg_size);

  return MT_SUCCESS;
}

static int init_nan_end_close1(mt_recv_args_t args, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte* pid = tor_malloc(DIGEST_LEN);
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(relay.chns_transition, (char*)pid, chn);
  chn->cb_args = args;

  // intiate token
  nan_end_close1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_nan_end_close1(&token, (byte (*)[DIGEST_LEN])&pid, &msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE1, msg, msg_size);

  return MT_SUCCESS;
}

/******************************* Channel Escrow *************************/

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  digestmap_remove(relay.chns_transition, (char*)*pid);
  byte intermediary_digest[DIGEST_LEN]; //how do we get this? side channel?
  digestmap_set(relay.chns_setup, (char*)intermediary_digest, chn);

  mt_recv_args_t args = chn->cb_args;
  return mt_rpay_recv(args.desc, args.type, args.msg, args.size);
}

/****************************** Channel Establish ***********************/

static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  // TODO assign channel or setup new micro channel if none exists
  //    put the channel in transition

  chn_end_estab3_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_chn_end_estab3(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_CHN_END_ESTAB3, resp_msg, resp_size);

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

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_set(relay.chns_estab, (char*)digest, chn);

  mt_recv_args_t args = chn->cb_args;
  return mt_rpay_recv(args.desc, args.type, args.msg, args.size);
}

/****************************** Nano Establish **************************/

static int handle_nan_cli_estab1(mt_desc_t* desc, nan_cli_estab1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // make sure there is a intermediary in the intermediary store otherwise return error
  mt_desc_t intermediary;

  // check validity of incoming message;

  mt_channel_t* chn;
  byte intermediary_digest[DIGEST_LEN];
  smartlist_t* nansetup_list = digestmap_get(relay.chns_nansetup, (char*)intermediary_digest);

  // we have a free channel with this intermediary
  if(nansetup_list != NULL && (chn = smartlist_pop_last(nansetup_list)) != NULL){
    digestmap_set(relay.chns_transition, (char*)*pid, chn);
    chn->cb_args.msg = NULL;
    chn->idesc = intermediary;
    //digestmap_set(relay.nanestab_state, *pid, chn);

    // start request for token and exit
  }

  // prepare args for callback
  mt_recv_args_t args = {.desc = desc, .type = MT_NTYPE_NAN_CLI_ESTAB1};
  args.size = pack_nan_cli_estab1(token, pid, &args.msg);

  // establish a new channel
  smartlist_t* estab_list = digestmap_get(relay.chns_estab, (char*)intermediary_digest);
  if(estab_list != NULL && (chn = smartlist_pop_last(estab_list)) != NULL){
    return init_chn_end_estab1(args, NULL, desc);
  }

  // setup a new channel
  smartlist_t* setup_list = digestmap_get(relay.chns_setup, (char*)intermediary_digest);
  if(setup_list != NULL && (chn = smartlist_pop_last(setup_list)) != NULL){
    return init_chn_end_setup(args, NULL, desc);
  }

  // something went wrong
  return MT_ERROR;
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

  nan_rel_estab4_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_estab4(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_REL_ESTAB4, resp_msg, resp_size);

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

  nan_rel_estab6_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_estab6(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_REL_ESTAB6, resp_msg, resp_size);

  // TODO remove channel from transition and declare it as established
  // don't need to notify anyone...


  byte client_desc[DIGEST_LEN]; //TODO: retrieve
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_set(relay.chns_nanestab, (char*)client_desc, chn);

  return MT_SUCCESS;
}

/******************************* Nano Pay *******************************/

static int handle_nan_cli_pay1(mt_desc_t* desc, nan_cli_pay1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_rel_pay2_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_pay2(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_REL_PAY2, resp_msg, resp_size);

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_set(relay.chns_nanestab, (char*)digest, chn);

  //  mt_alert_payment(desc);
  return MT_SUCCESS;
}

/*************************** Nano Req Close *****************************/

static int handle_nan_cli_reqclose1(mt_desc_t* desc, nan_cli_reqclose1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  if((chn = digestmap_remove(relay.chns_nanestab, (char*)digest)) != NULL){
    mt_recv_args_t args = {.desc = desc, .type = MT_NTYPE_NAN_INT_CLOSE2};
    args.size = pack_nan_cli_reqclose1(token, pid, &args.msg);
    return init_nan_end_close1(args, chn, desc);
  }

  nan_rel_reqclose2_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_reqclose2(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_REL_REQCLOSE2, resp_msg, resp_size);

  return MT_SUCCESS;
}

/******************************* Nano Close *****************************/

static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close3_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_end_close3(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE3, resp_msg, resp_size);

  return MT_SUCCESS;
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

  nan_end_close5_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_end_close5(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE5, resp_msg, resp_size);

  return MT_SUCCESS;
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

  nan_end_close7_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_end_close7(&response, pid, &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE7, resp_msg, resp_size);

  return MT_SUCCESS;
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

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_set(relay.chns_nanestab, (char*)digest, chn);

  // start creating token

  mt_recv_args_t args = chn->cb_args;
  return mt_rpay_recv(args.desc, args.type, args.msg, args.size);
}
