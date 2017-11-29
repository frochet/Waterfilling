#pragma GCC diagnostic ignored "-Wswitch-enum"


//TODO pending business is a mess; do something to ensure thread-safety


#include<pthread.h>

#include "or.h"
#include "mt_common.h"
#include "mt_rpay.h"

typedef enum {
  STATUS_PENDING,
  STATUS_READY,
} status_t;

typedef struct {
  mt_desc_t cdesc;
  mt_desc_t idesc;
  chn_end_data_t data;

  mt_event_notify_t callback;
  mt_desc_t callback_desc;

  status_t nanestab_tkn_status;
  status_t nanestab_int_status;
  nan_rel_estab2_t nanestab_tkn;
} mt_channel_t;

/**
 * Single instance of a relay payment object
 */
typedef struct {

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte addr[MT_SZ_ADDR];

  smartlist_t* chns_setup;
  smartlist_t* chns_estab;
  smartlist_t* chns_nansetup;
  digestmap_t* chns_nanestab;    // desc -> channel
  digestmap_t* chns_transition;  // proto_id -> channel
} mt_rpay_t;

static mt_rpay_t relay;

// local handler functions
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_cli_estab1(mt_desc_t* desc, nan_cli_estab1_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_int_estab3(mt_desc_t* desc, nan_int_estab3_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_cli_pay1(mt_desc_t* desc, nan_cli_pay1_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*proto_id)[DIGEST_LEN]);
static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*proto_id)[DIGEST_LEN]);

static int finish_nan_cli_estab1(byte (*proto_id)[DIGEST_LEN]);

// Tor-facing API
int mt_rpay_init(void){

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];

  // copy macro-level crypto fields
  memcpy(relay.pp, pp, MT_SZ_PP);
  memcpy(relay.pk, pk, MT_SZ_PK);
  memcpy(relay.sk, sk, MT_SZ_SK);

  // initiate containers
  relay.chns_setup = smartlist_new();
  relay.chns_estab = smartlist_new();
  relay.chns_nansetup = smartlist_new();
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
  byte proto_id[DIGEST_LEN];

  switch(type){
    case MT_NTYPE_ANY_LED_CONFIRM:;
      any_led_confirm_t any_led_confirm_tkn;
      if(unpack_any_led_confirm(msg, size, &any_led_confirm_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_any_led_confirm(desc, &any_led_confirm_tkn, &proto_id);
      break;

    case MT_NTYPE_CHN_INT_ESTAB2:;
      chn_int_estab2_t chn_int_estab2_tkn;
      if(unpack_chn_int_estab2(msg, size, &chn_int_estab2_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab2(desc, &chn_int_estab2_tkn, &proto_id);
      break;

    case MT_NTYPE_CHN_INT_ESTAB4:;
      chn_int_estab4_t chn_int_estab4_tkn;
      if(unpack_chn_int_estab4(msg, size, &chn_int_estab4_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab4(desc, &chn_int_estab4_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_CLI_ESTAB1:;
      nan_cli_estab1_t nan_cli_estab1_tkn;
      if(unpack_nan_cli_estab1(msg, size, &nan_cli_estab1_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_estab1(desc, &nan_cli_estab1_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_INT_ESTAB3:;
      nan_int_estab3_t nan_int_estab3_tkn;
      if(unpack_nan_int_estab3(msg, size, &nan_int_estab3_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_estab3(desc, &nan_int_estab3_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_INT_ESTAB5:;
      nan_int_estab5_t nan_int_estab5_tkn;
      if(unpack_nan_int_estab5(msg, size, &nan_int_estab5_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_estab5(desc, &nan_int_estab5_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_CLI_PAY1:;
      nan_cli_pay1_t nan_cli_pay1_tkn;
      if(unpack_nan_cli_pay1(msg, size, &nan_cli_pay1_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_pay1(desc, &nan_cli_pay1_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_INT_CLOSE2:;
      nan_int_close2_t nan_int_close2_tkn;
      if(unpack_nan_int_close2(msg, size, &nan_int_close2_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close2(desc, &nan_int_close2_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_INT_CLOSE4:;
      nan_int_close4_t nan_int_close4_tkn;
      if(unpack_nan_int_close4(msg, size, &nan_int_close4_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close4(desc, &nan_int_close4_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_INT_CLOSE6:;
      nan_int_close6_t nan_int_close6_tkn;
      if(unpack_nan_int_close6(msg, size, &nan_int_close6_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close6(desc, &nan_int_close6_tkn, &proto_id);
      break;

    case MT_NTYPE_NAN_INT_CLOSE8:;
      nan_int_close8_t nan_int_close8_tkn;
      if(unpack_nan_int_close8(msg, size, &nan_int_close8_tkn, &proto_id) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close8(desc, &nan_int_close8_tkn, &proto_id);
      break;

    default:
      result = MT_ERROR;
  }
  return result;
}

int mt_rpay_notify_connect(mt_desc_t* desc){
  (void)desc;

  // use intermediary mapping to find relay

  //mt_channel_t* chn; // retrieve this from
  // update the intermediary connection to "ready"
  //     mapping between intermediary and proto_id
  //     can then use proto_id to find item on transitions list

  byte proto_id[DIGEST_LEN];
  return finish_nan_cli_estab1(&proto_id);
}

/**************************** Initialize Protocols **********************/

static int init_chn_end_escrow(mt_event_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  mt_desc_t* intermediary;
  if(mt_new_intermediary(intermediary) != MT_SUCCESS)
    return MT_ERROR;

  // initialize new channel
  chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(&chn->idesc, intermediary, sizeof(mt_desc_t));
  memcpy(chn->data.pk, relay.pk, MT_SZ_PK);
  memcpy(chn->data.sk, relay.pk, MT_SZ_PK);

  // TODO finish initializing channel

  byte proto_id[DIGEST_LEN];
  mt_crypt_rand_bytes(DIGEST_LEN, proto_id);
  digestmap_set(relay.chns_transition, (char*)proto_id, chn);
  chn->callback = notify;
  chn->callback_desc = *desc;

  // initialize escrow token
  chn_end_escrow_t token;

  // TODO finish making escrow token

  // send escrow message
  byte* msg;
  int msg_size = pack_chn_end_escrow(&token, (byte (*)[DIGEST_LEN])&proto_id, &msg);
  send_message(desc, MT_NTYPE_CHN_END_ESCROW, msg, msg_size);

  return MT_SUCCESS;
}

static int init_nan_end_close1(mt_event_notify_t notify, mt_channel_t* chn, mt_desc_t* desc){

  // add new protocol to chns_transition
  byte* proto_id = tor_malloc(DIGEST_LEN);
  mt_crypt_rand_bytes(DIGEST_LEN, proto_id);
  digestmap_set(relay.chns_transition, (char*)proto_id, chn);
  chn->callback = notify;
  chn->callback_desc = *desc;

  // intiate token
  nan_end_close1_t token;

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_nan_end_close1(&token, (byte (*)[DIGEST_LEN])&proto_id, &msg);
  send_message(desc, MT_NTYPE_NAN_END_CLOSE1, msg, msg_size);

  return MT_SUCCESS;
}

/******************************* Channel Escrow *************************/

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  digestmap_remove(relay.chns_transition, (char*)*proto_id);
  smartlist_add(relay.chns_setup, chn);

  chn->callback(&chn->callback_desc, MT_SUCCESS);
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  // TODO assign channel or setup new micro channel if none exists
  //    put the channel in transition

  chn_end_estab3_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_chn_end_estab3(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_CHN_END_ESTAB3, resp_msg, resp_size);

  return MT_SUCCESS;
}

static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  digestmap_remove(relay.chns_transition, (char*)*proto_id);
  digestmap_set(relay.chns_estab, (char*)*proto_id, chn);

  chn->callback(&chn->callback_desc, MT_SUCCESS);
  return MT_SUCCESS;
}

/****************************** Nano Establish **************************/

static int handle_nan_cli_estab1(mt_desc_t* desc, nan_cli_estab1_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // make sure there is a intermediary in the intermediary store otherwise return error

  // check validity of incoming message;

  mt_channel_t* chn;
  if(chn = smartlist_pop_last(relay.chns_nansetup)){
    digestmap_set(relay.chns_transition, *proto_id, chn);
    chn->callback = NULL;
    chn->cdesc = *desc;
    //chn->idesc = ; // intermediary store

    //digestmap_set(relay.nanestab_state, *proto_id, chn);

    // fill in token at chn.nanestab_tkn

    chn->nanestab_tkn_status = STATUS_READY;
    return finish_nan_cli_estab(proto_id);
  }

  return init_chn_end_escrow(handle_nan_cli_estab1, NULL, desc);
}

static int handle_nan_int_estab3(mt_desc_t* desc, nan_int_estab3_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_rel_estab4_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_estab4(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_REL_ESTAB4, resp_msg, resp_size);

  return MT_SUCCESS;
}

static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_rel_estab6_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_estab6(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_REL_ESTAB6, resp_msg, resp_size);

  // TODO remove channel from transition and declare it as established
  // don't need to notify anyone...


  digestmap_remove(relay.chns_transition, (char*)*proto_id);
  digestmap_set(relay.chns_nanestab, (char*)*proto_id, chn);

  return MT_SUCCESS;
}

/******************************* Nano Pay *******************************/

static int handle_nan_cli_pay1(mt_desc_t* desc, nan_cli_pay1_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_rel_pay2_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_pay2(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_REL_PAY2, resp_msg, resp_size);

  digestmap_remove(relay.chns_transition, (char*)*proto_id);
  digestmap_set(relay.chns_nanestab, (char*)*proto_id, chn);

  alert_payment(desc);
  return MT_SUCCESS;
}

/****************************** Nano Req Close **************************/

static int handle_nan_cli_reqclose1(mt_desc_t* desc, nan_int_close2_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  // check validity of incoming message;

  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  if((chn = digestmap_remove(relay.chns_nanestab, (char*)digest)) != NULL)
    return init_nan_end_close1(handle_nan_cli_reqclose1, chn, desc);

  nan_rel_reqclose2_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_rel_reqclose2(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_REL_REQCLOSE2, resp_msg, resp_size);

  return MT_SUCCESS;
}

/******************************* Nano Close *****************************/

static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close3_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_end_close3(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_END_CLOSE3, resp_msg, resp_size);

  return MT_SUCCESS;
}

static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close5_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_end_close5(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_END_CLOSE5, resp_msg, resp_size);

  return MT_SUCCESS;
}

static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close7_t response;

  // fill response with correct values;

  byte* resp_msg;
  int resp_size = pack_nan_end_close7(&response, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_END_CLOSE7, resp_msg, resp_size);

  return MT_SUCCESS;
}

static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*proto_id)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*proto_id);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  digestmap_remove(relay.chns_transition, (char*)*proto_id);
  digestmap_set(relay.chns_nanestab, (char*)*proto_id, chn);

  chn->callback(&chn->callback_desc, MT_SUCCESS);
  return MT_SUCCESS;
}

// TODO: this needs to be mutexed somehow
static int finish_nan_cli_estab1(byte(*proto_id)[DIGEST_LEN]){

  mt_desc_t* desc; // this should be retrieved from mapping

  // if intermediary is not ready or the token is not ready then return

  nan_rel_estab2_t token;

  // prepare token

  byte* resp_msg;
  int resp_size = pack_nan_rel_estab2(&token, proto_id, &resp_msg);
  send_message(desc, MT_NTYPE_NAN_REL_ESTAB2, resp_msg, resp_size);
}
