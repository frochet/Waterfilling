#pragma GCC diagnostic ignored "-Wswitch-enum"

#include "or.h"
#include "workqueue.h"
#include "mt_common.h"
#include "mt_ipay.h"

typedef struct {
  mt_desc_t* desc;
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
  byte chn[MT_SZ_ADDR];

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

  chn_int_state_t chn_state;
  nan_int_state_t nan_state;

  digestmap_t* chns_setup;       // desc -> chn
  digestmap_t* chns_estab;       // desc -> chn

  digestmap_t* chns_transition;  // proto_id -> chn
} mt_ipay_t;


// private initializer functions
static int init_chn_int_setup(mt_recv_args_t* args, mt_channel_t* chn, mt_desc_t* desc);

// local handler functions
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_end_estab1(mt_desc_t* desc, chn_end_estab1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_end_estab3(mt_desc_t* desc, chn_end_estab3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup1(mt_desc_t* desc, nan_cli_setup1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup3(mt_desc_t* desc, nan_cli_setup3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup5(mt_desc_t* desc, nan_cli_setup5_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab2(mt_desc_t* desc, nan_rel_estab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab4(mt_desc_t* desc, nan_rel_estab4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*pid)[DIGEST_LEN]);
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

  /********************************************************************/


  // copy macro-level crypto fields
  memcpy(intermediary.pp, pp, MT_SZ_PP);
  memcpy(intermediary.pk, pk, MT_SZ_PK);
  memcpy(intermediary.sk, sk, MT_SZ_SK);
  intermediary.ledger = ledger;

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

    case MT_NTYPE_NAN_INT_ESTAB5:;
      nan_int_estab5_t nan_int_estab5_tkn;
      if(unpack_nan_int_estab5(msg, size, &nan_int_estab5_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_estab5(desc, &nan_int_estab5_tkn, &pid);
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

static int init_chn_int_setup(mt_recv_args_t* args, mt_channel_t* chn, mt_desc_t* desc){
  (void)args;
  (void)chn;
  (void)desc;
  return MT_SUCCESS;
}

/******************************* Channel Escrow *************************/

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int handle_chn_end_estab1(mt_desc_t* desc, chn_end_estab1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;

  init_chn_int_setup(NULL, NULL, desc); // just to get rid of warning for now
  return MT_SUCCESS;
}

static int handle_chn_end_estab3(mt_desc_t* desc, chn_end_estab3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

/******************************** Nano Setup ****************************/

static int handle_nan_cli_setup1(mt_desc_t* desc, nan_cli_setup1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

static int handle_nan_cli_setup3(mt_desc_t* desc, nan_cli_setup3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

static int handle_nan_cli_setup5(mt_desc_t* desc, nan_cli_setup5_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

/**************************** Nano Establish ****************************/

static int handle_nan_rel_estab2(mt_desc_t* desc, nan_rel_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

static int handle_nan_rel_estab4(mt_desc_t* desc, nan_rel_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

/************************ Nano Direct Establish *************************/

static int handle_nan_cli_destab1(mt_desc_t* desc, nan_cli_destab1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

/**************************** Nano Direct Pay ***************************/

static int handle_nan_cli_dpay1(mt_desc_t* desc, nan_cli_dpay1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

/******************************* Nano Close *****************************/

static int handle_nan_end_close1(mt_desc_t* desc, nan_end_close1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

static int handle_nan_end_close3(mt_desc_t* desc, nan_end_close3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

static int handle_nan_end_close5(mt_desc_t* desc, nan_end_close5_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}

static int handle_nan_end_close7(mt_desc_t* desc, nan_end_close7_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;
  (void)token;
  (void)pid;
  return MT_SUCCESS;
}
