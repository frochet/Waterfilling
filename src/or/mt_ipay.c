#pragma GCC diagnostic ignored "-Wswitch-enum"

#include "or.h"
#include "workqueue.h"
#include "mt_common.h"
#include "mt_ipay.h"

typedef struct {
  mt_desc_t desc;
  mt_ntype_t type;
  byte* msg;
  int size;
} mt_recv_args_t;

typedef enum {
  MT_ZKP_STATE_NONE,
  MT_ZKP_STATE_STARTED,
  MT_ZKP_STATE_READY,
} mt_zkp_state_t;

typedef struct {
  byte addr[MT_SZ_ADDR];

  mt_desc_t end_desc;
  chn_int_chntok_t chn_token;

  mt_recv_args_t cb_args;
} mt_channel_t;

/**
 * Single instance of an intermediary payment object
 */
typedef struct {
  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte addr[MT_SZ_ADDR];

  mt_desc_t ledger;
  int fee;

  chn_int_state_t chn_state;
  nan_int_state_t nan_state;

  digestmap_t* chns_setup;       // desc -> chn
  digestmap_t* chns_estab;       // desc -> chn

  digestmap_t* chns_transition;  // proto_id -> chn
} mt_ipay_t;


// private initializer functions
static int init_chn_int_setup(mt_recv_args_t* args, byte (*chn_addr)[MT_SZ_ADDR], mt_desc_t* desc);

// local handler functions
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_end_estab1(mt_desc_t* desc, chn_end_estab1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_end_estab3(mt_desc_t* desc, chn_end_estab3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup1(mt_desc_t* desc, nan_cli_setup1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup3(mt_desc_t* desc, nan_cli_setup3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup5(mt_desc_t* desc, nan_cli_setup5_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab2(mt_desc_t* desc, nan_rel_estab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab4(mt_desc_t* desc, nan_rel_estab4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_destab1(mt_desc_t* desc, nan_cli_destab1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_dpay1(mt_desc_t* desc, nan_cli_dpay1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close1(mt_desc_t* desc, nan_end_close1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close3(mt_desc_t* desc, nan_end_close3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close5(mt_desc_t* desc, nan_end_close5_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close7(mt_desc_t* desc, nan_end_close7_t* token, byte (*pid)[DIGEST_LEN]);

static mt_ipay_t intermediary;

int mt_ipay_init(void){

  // TODO: load in keys

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

  fp = fopen("mt_config_temp/int_pk", "rb");
  tor_assert(fread(pk, 1, MT_SZ_PK, fp) == MT_SZ_PK);
  fclose(fp);

  fp = fopen("mt_config_temp/int_sk", "rb");
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
  memcpy(intermediary.pp, pp, MT_SZ_PP);
  memcpy(intermediary.pk, pk, MT_SZ_PK);
  memcpy(intermediary.sk, sk, MT_SZ_SK);
  mt_pk2addr(&intermediary.pk, &intermediary.addr);
  intermediary.ledger = ledger;
  intermediary.fee = fee;

  // initialize channel containers
  intermediary.chns_setup = digestmap_new();
  intermediary.chns_estab = digestmap_new();
  intermediary.chns_transition = digestmap_new();

  return MT_SUCCESS;
}

int mt_ipay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size){

  int result;
  byte pid[DIGEST_LEN];

  switch(type){
    case MT_NTYPE_ANY_LED_CONFIRM:;
      any_led_confirm_t any_led_confirm_tkn;
      if(unpack_any_led_confirm(msg, size, &any_led_confirm_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_any_led_confirm(desc, &any_led_confirm_tkn, &pid);
      break;

    case MT_NTYPE_CHN_END_ESTAB1:;
      chn_end_estab1_t chn_end_estab1_tkn;
      if(unpack_chn_end_estab1(msg, size, &chn_end_estab1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_end_estab1(desc, &chn_end_estab1_tkn, &pid);
      break;

    case MT_NTYPE_CHN_END_ESTAB3:;
      chn_end_estab3_t chn_end_estab3_tkn;
      if(unpack_chn_end_estab3(msg, size, &chn_end_estab3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_end_estab3(desc, &chn_end_estab3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_SETUP1:;
      nan_cli_setup1_t nan_cli_setup1_tkn;
      if(unpack_nan_cli_setup1(msg, size, &nan_cli_setup1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_setup1(desc, &nan_cli_setup1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_SETUP3:;
      nan_cli_setup3_t nan_cli_setup3_tkn;
      if(unpack_nan_cli_setup3(msg, size, &nan_cli_setup3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_setup3(desc, &nan_cli_setup3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_SETUP5:;
      nan_cli_setup5_t nan_cli_setup5_tkn;
      if(unpack_nan_cli_setup5(msg, size, &nan_cli_setup5_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_setup5(desc, &nan_cli_setup5_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_ESTAB2:;
      nan_rel_estab2_t nan_rel_estab2_tkn;
      if(unpack_nan_rel_estab2(msg, size, &nan_rel_estab2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_estab2(desc, &nan_rel_estab2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_ESTAB4:;
      nan_rel_estab4_t nan_rel_estab4_tkn;
      if(unpack_nan_rel_estab4(msg, size, &nan_rel_estab4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_estab4(desc, &nan_rel_estab4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_DESTAB1:;
      nan_cli_destab1_t nan_cli_destab1_tkn;
      if(unpack_nan_cli_destab1(msg, size, &nan_cli_destab1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_destab1(desc, &nan_cli_destab1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_DPAY1:;
      nan_cli_dpay1_t nan_cli_dpay1_tkn;
      if(unpack_nan_cli_dpay1(msg, size, &nan_cli_dpay1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_dpay1(desc, &nan_cli_dpay1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE1:;
      nan_end_close1_t nan_end_close1_tkn;
      if(unpack_nan_end_close1(msg, size, &nan_end_close1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close1(desc, &nan_end_close1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE3:;
      nan_end_close3_t nan_end_close3_tkn;
      if(unpack_nan_end_close3(msg, size, &nan_end_close3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close3(desc, &nan_end_close3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE5:;
      nan_end_close5_t nan_end_close5_tkn;
      if(unpack_nan_end_close5(msg, size, &nan_end_close5_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close5(desc, &nan_end_close5_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE7:;
      nan_end_close7_t nan_end_close7_tkn;
      if(unpack_nan_end_close7(msg, size, &nan_end_close7_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close7(desc, &nan_end_close7_tkn, &pid);
      break;

    default:
      result = MT_ERROR;
  }

  return result;
}

/**************************** Initialize Protocols **********************/

static int init_chn_int_setup(mt_recv_args_t* args, byte (*chn_addr)[MT_SZ_ADDR], mt_desc_t* desc){

  // initialize new channel
  mt_channel_t* chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(&chn->addr, chn_addr, MT_SZ_ADDR);
  memcpy(&chn->end_desc, desc, sizeof(mt_desc_t));
  memcpy(&chn->cb_args, args, sizeof(mt_recv_args_t));
  // ignore channel token for now

  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);
  digestmap_set(intermediary.chns_transition, (char*)pid, chn);

  // initialize setup token
  chn_int_setup_t token;
  token.val_from = 50 + intermediary.fee;
  token.val_to = 50;
  memcpy(token.from, intermediary.addr, MT_SZ_ADDR);
  memcpy(token.chn, chn->addr, MT_SZ_ADDR);
  // ignore channel token for now

  // send setup message
  byte* packed_reply;
  byte* signed_reply;
  int packed_reply_size = pack_chn_int_setup(&token, &pid, &packed_reply);
  int signed_reply_size = mt_create_signed_msg(packed_reply, packed_reply_size,
					     &intermediary.pk, &intermediary.sk, &signed_reply);
  return mt_send_message(&intermediary.ledger, MT_NTYPE_CHN_INT_SETUP, signed_reply, signed_reply_size);
}

/******************************* Channel Escrow *************************/

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){

  mt_channel_t* chn = digestmap_get(intermediary.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message

  // move channel to chns_setup
  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->end_desc, &digest);
  digestmap_remove(intermediary.chns_transition, (char*)*pid);
  digestmap_set(intermediary.chns_setup, digest, chn);

  mt_recv_args_t args = chn->cb_args;
  if(args.msg != NULL){
    return mt_ipay_recv(&args.desc, args.type, args.msg, args.size);
  }
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int handle_chn_end_estab1(mt_desc_t* desc, chn_end_estab1_t* token, byte (*pid)[DIGEST_LEN]){

  // verify token validity

  // setup chn
  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  // if existing channel is setup with this address then start establish protocol
  if((chn = digestmap_remove(intermediary.chns_setup, (char*)digest)) != NULL){

    // add channel to transition
    digestmap_set(intermediary.chns_transition, (char*)pid, chn);

    chn_int_estab2_t reply;

    // fill out token

    chn->cb_args.msg = NULL;
    byte* packed_reply;
    int packed_reply_size = pack_chn_int_estab2(&reply, pid, &packed_reply);
    return mt_send_message(desc, MT_NTYPE_CHN_INT_ESTAB2, packed_reply, packed_reply_size);
  }

  // otherwise prepare callback
  mt_recv_args_t args;
  args.type = MT_NTYPE_CHN_END_ESTAB1;
  memcpy(&args.desc, desc, sizeof(mt_desc_t));
  args.size = pack_chn_end_estab1(token, pid, &args.msg);

  init_chn_int_setup(&args, &token->addr, desc); // just to get rid of warning for now
  return MT_SUCCESS;
}

static int handle_chn_end_estab3(mt_desc_t* desc, chn_end_estab3_t* token, byte (*pid)[DIGEST_LEN]){

  mt_channel_t* chn = digestmap_get(intermediary.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(intermediary.chns_transition, (char*)*pid);
  digestmap_set(intermediary.chns_estab, (char*)digest, chn);

  chn_int_estab4_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_chn_int_estab4(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_CHN_INT_ESTAB4, packed_reply, packed_reply_size);
}

/******************************** Nano Setup ****************************/

static int handle_nan_cli_setup1(mt_desc_t* desc, nan_cli_setup1_t* token, byte (*pid)[DIGEST_LEN]){

  // verify token validity

  nan_int_setup2_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_setup2(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_SETUP2, packed_reply, packed_reply_size);
}

static int handle_nan_cli_setup3(mt_desc_t* desc, nan_cli_setup3_t* token, byte (*pid)[DIGEST_LEN]){

  // verify token validity

  nan_int_setup4_t reply;

  // fill reply with correct values

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_setup4(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_SETUP4, packed_reply, packed_reply_size);
}

static int handle_nan_cli_setup5(mt_desc_t* desc, nan_cli_setup5_t* token, byte (*pid)[DIGEST_LEN]){

  // verify token validity

  nan_int_setup6_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_setup6(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_SETUP6, packed_reply, packed_reply_size);
}

/**************************** Nano Establish ****************************/

static int handle_nan_rel_estab2(mt_desc_t* desc, nan_rel_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_estab3_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_estab3(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_ESTAB3, packed_reply, packed_reply_size);
}

static int handle_nan_rel_estab4(mt_desc_t* desc, nan_rel_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_estab5_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_estab5(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_ESTAB5, packed_reply, packed_reply_size);
}

/************************ Nano Direct Establish *************************/

static int handle_nan_cli_destab1(mt_desc_t* desc, nan_cli_destab1_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_destab2_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_destab2(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_DESTAB2, packed_reply, packed_reply_size);
}

/**************************** Nano Direct Pay ***************************/

static int handle_nan_cli_dpay1(mt_desc_t* desc, nan_cli_dpay1_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_dpay2_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_dpay2(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_DPAY2, packed_reply, packed_reply_size);
}

/******************************* Nano Close *****************************/

static int handle_nan_end_close1(mt_desc_t* desc, nan_end_close1_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_close2_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_close2(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_CLOSE2, packed_reply, packed_reply_size);
}

static int handle_nan_end_close3(mt_desc_t* desc, nan_end_close3_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_close4_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_close4(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_CLOSE4, packed_reply, packed_reply_size);
}

static int handle_nan_end_close5(mt_desc_t* desc, nan_end_close5_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_close6_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_close6(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_CLOSE6, packed_reply, packed_reply_size);
}

static int handle_nan_end_close7(mt_desc_t* desc, nan_end_close7_t* token, byte (*pid)[DIGEST_LEN]){
  // verify token validity

  nan_int_close8_t reply;

  // fill out token

  byte* packed_reply;
  int packed_reply_size = pack_nan_int_close8(&reply, pid, &packed_reply);
  return mt_send_message(desc, MT_NTYPE_NAN_INT_CLOSE8, packed_reply, packed_reply_size);
}
