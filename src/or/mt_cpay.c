/**
 * \file mt_cpay.h
 * \brief Header file for mt_cpay.c
 **/

#pragma GCC diagnostic ignored "-Wswitch-enum"

#include "or.h"
#include "mt_common.h"
#include "mt_cpay.h"

#define MT_FREE 1
#define MT_TAKEN 2

// private handler functions
static int handle_chn_int_estab2(mt_desc_t desc, chn_int_estab2_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_chn_int_estab4(mt_desc_t desc, chn_int_estab4_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_mic_rel_pay2(mt_desc_t desc, mic_rel_pay2_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_mic_int_pay4(mt_desc_t desc, mic_int_pay4_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_mic_int_pay7(mt_desc_t desc, mic_int_pay7_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_setup2(mt_desc_t desc, nan_int_setup2_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_setup4(mt_desc_t desc, nan_int_setup4_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_setup6(mt_desc_t desc, nan_int_setup6_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_direct2(mt_desc_t desc, nan_int_direct2_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_rel_estab6(mt_desc_t desc, nan_rel_estab6_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_rel_pay2(mt_desc_t desc, nan_rel_pay2_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_close2(mt_desc_t desc, nan_int_close2_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_close4(mt_desc_t desc, nan_int_close4_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_close6(mt_desc_t desc, nan_int_close6_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_nan_int_close8(mt_desc_t desc, nan_int_close8_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_mac_led_data(mt_desc_t desc, mac_led_data_t* token, byte (*pk)[MT_SZ_PK]);
static int handle_chn_led_data(mt_desc_t desc, chn_led_data_t* token, byte (*pk)[MT_SZ_PK]);

// private helper functions
static int compare_chn_end_data(const void** a, const void** b);

typedef struct {
  int is_free;
  mt_desc_t rdesc;
  mt_desc_t idesc;
  chn_end_data_t* data;
} mt_channel_t;

// TODO: this should be moved to or.h
typedef void (*mt_event_notify_t)(mt_desc_t, int);

void mt_send_message(mt_desc_t desc, mt_ntype_t type, byte* msg, int msg_size);

typedef struct {
  mt_event_notify_t callback;
  int time_started;
} mt_request_t;

/**
 * Single instance of a client payment object
 */
typedef struct {

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte addr[MT_SZ_ADDR];

  smartlist_t* chns_free;    // channels that are ready to be used
  digestmap_t* chns_taken;   // channels attached to relay/intermediary
  digestmap_t* req_queue;    // map descriptor digests to mt_request_t
} mt_cpay_t;

static mt_cpay_t client;

int mt_cpay_init(void){

  // these should all be loaded in from tor state somehow
  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  mt_channel_t* channels;
  int num_chns;

  // copy macro-level crypto fields
  memcpy(client.pp, pp, MT_SZ_PP);
  memcpy(client.pk, pk, MT_SZ_PK);
  memcpy(client.sk, sk, MT_SZ_SK);

  // initiate containers
  client.chns_free = smartlist_new();
  client.chns_taken = digestmap_new();
  client.req_queue = digestmap_new();

  // if existing channels are provided then record them
  if(num_chns > 0){
    for(int i = 0; i < num_chns; i++){
      mt_channel_t* chn = tor_malloc(sizeof(mt_channel_t));
      memcpy(chn, channels + i, sizeof(mt_channel_t));
      chn->is_free = MT_FREE;
      smartlist_add(client.chns_free, chn);
    }
  }

  // sort channel balances from highest to lowest
  smartlist_sort(client.chns_free, compare_chn_end_data);
  return MT_SUCCESS;
}

int mt_cpay_directpay(mt_desc_t desc){
  (void)desc;
  // if payment is established w/ descriptor
  //    start first payment message
  //    set callback as controller notifier
  //    return

  // otherwise
  //    allocate new funds
  //    start first setup method
  //    set callback as this method
  //    return
  return 0;
}

int mt_cpay_pay(mt_desc_t desc){
  (void)desc;

  // if payment is established w/ descriptor
  //    start first payment message
  //    set callback as controller notifier
  //    return

  // if we have a free channel
  //    start first establish method
  //    set callback as this method
  //    return

  // otherwise
  //    allocate new funds
  //    start first setup method
  //    set callback as this method
  //    return

  return 0;
}

int mt_cpay_close(mt_desc_t desc){
  (void) desc;

  // if channel isn't open
  //    return error

  // otherwise
  //    start first close message
  //    set callback to controller
  //    return

  return 0;
}

int mt_cpay_recv(mt_desc_t desc, mt_ntype_t type, byte* msg, int size){

  int result;
  byte pk_from[MT_SZ_PK];

  switch(type){
    case MT_NTYPE_CHN_INT_ESTAB2:;
      chn_int_estab2_t chn_int_estab2_tkn;
      if(unpack_chn_int_estab2(msg, size, &chn_int_estab2_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab2(desc, &chn_int_estab2_tkn, &pk_from);
      break;
    case MT_NTYPE_CHN_INT_ESTAB4:;
      chn_int_estab4_t chn_int_estab4_tkn;
      if(unpack_chn_int_estab4(msg, size, &chn_int_estab4_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab4(desc, &chn_int_estab4_tkn, &pk_from);
    case MT_NTYPE_MIC_REL_PAY2:;
      mic_rel_pay2_t mic_rel_pay2_tkn;
      if(unpack_mic_rel_pay2(msg, size, &mic_rel_pay2_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_mic_rel_pay2(desc, &mic_rel_pay2_tkn, &pk_from);
    case MT_NTYPE_MIC_INT_PAY4:;
      mic_int_pay4_t mic_int_pay4_tkn;
      if(unpack_mic_int_pay4(msg, size, &mic_int_pay4_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_mic_int_pay4(desc, &mic_int_pay4_tkn, &pk_from);
    case MT_NTYPE_MIC_INT_PAY7:;
      mic_int_pay7_t mic_int_pay7_tkn;
      if(unpack_mic_int_pay7(msg, size, &mic_int_pay7_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_mic_int_pay7(desc, &mic_int_pay7_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_SETUP2:;
      nan_int_setup2_t nan_int_setup2_tkn;
      if(unpack_nan_int_setup2(msg, size, &nan_int_setup2_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup2(desc, &nan_int_setup2_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_SETUP4:;
      nan_int_setup4_t nan_int_setup4_tkn;
      if(unpack_nan_int_setup4(msg, size, &nan_int_setup4_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup4(desc, &nan_int_setup4_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_SETUP6:;
      nan_int_setup6_t nan_int_setup6_tkn;
      if(unpack_nan_int_setup6(msg, size, &nan_int_setup6_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup6(desc, &nan_int_setup6_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_DIRECT2:;
      nan_int_direct2_t nan_int_direct2_tkn;
      if(unpack_nan_int_direct2(msg, size, &nan_int_direct2_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_direct2(desc, &nan_int_direct2_tkn, &pk_from);
    case MT_NTYPE_NAN_REL_ESTAB6:;
      nan_rel_estab6_t nan_rel_estab6_tkn;
      if(unpack_nan_rel_estab6(msg, size, &nan_rel_estab6_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_estab6(desc, &nan_rel_estab6_tkn, &pk_from);
    case MT_NTYPE_NAN_REL_PAY2:;
      nan_rel_pay2_t nan_rel_pay2_tkn;
      if(unpack_nan_rel_pay2(msg, size, &nan_rel_pay2_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_pay2(desc, &nan_rel_pay2_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_CLOSE2:;
      nan_int_close2_t nan_int_close2_tkn;
      if(unpack_nan_int_close2(msg, size, &nan_int_close2_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close2(desc, &nan_int_close2_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_CLOSE4:;
      nan_int_close4_t nan_int_close4_tkn;
      if(unpack_nan_int_close4(msg, size, &nan_int_close4_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close4(desc, &nan_int_close4_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_CLOSE6:;
      nan_int_close6_t nan_int_close6_tkn;
      if(unpack_nan_int_close6(msg, size, &nan_int_close6_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close6(desc, &nan_int_close6_tkn, &pk_from);
    case MT_NTYPE_NAN_INT_CLOSE8:;
      nan_int_close8_t nan_int_close8_tkn;
      if(unpack_nan_int_close8(msg, size, &nan_int_close8_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close8(desc, &nan_int_close8_tkn, &pk_from);
    case MT_NTYPE_MAC_LED_DATA:;
      mac_led_data_t mac_led_data_tkn;
      if(unpack_mac_led_data(msg, size, &mac_led_data_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_mac_led_data(desc, &mac_led_data_tkn, &pk_from);
    case MT_NTYPE_CHN_LED_DATA:;
      chn_led_data_t chn_led_data_tkn;
      if(unpack_chn_led_data(msg, size, &chn_led_data_tkn, &pk_from) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_led_data(desc, &chn_led_data_tkn, &pk_from);
    default:
      result = MT_ERROR;
      break;
  }

  return result;
}

/****************************** Channel Establish ***********************/

static int handle_chn_int_estab2(mt_desc_t desc, chn_int_estab2_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  chn_end_estab3_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_chn_end_estab3(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_CHN_END_ESTAB3, resp_msg, resp_size);
  return 0;
}

static int handle_chn_int_estab4(mt_desc_t desc, chn_int_estab4_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity of incoming message

  // !!! notify controller that establish is complete
  return 0;
}

/********************************** Micropay ****************************/

static int handle_mic_rel_pay2(mt_desc_t desc, mic_rel_pay2_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  mic_cli_pay3_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_mic_cli_pay3(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_MIC_CLI_PAY3, resp_msg, resp_size);

  return 0;
}

static int handle_mic_int_pay4(mt_desc_t desc, mic_int_pay4_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  mic_cli_pay5_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_mic_cli_pay5(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_MIC_CLI_PAY5, resp_msg, resp_size);
  return 0;
}

static int handle_mic_int_pay7(mt_desc_t desc, mic_int_pay7_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // !!! notify controller that pay is complete
  return 0;
}

/******************************** Nano Setup ****************************/

static int handle_nan_int_setup2(mt_desc_t desc, nan_int_setup2_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  nan_int_setup2_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_nan_int_setup2(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_INT_SETUP2, resp_msg, resp_size);

  return 0;
}

static int handle_nan_int_setup4(mt_desc_t desc, nan_int_setup4_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  nan_cli_setup5_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_nan_cli_setup5(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_CLI_SETUP5, resp_msg, resp_size);

  return 0;
}

static int handle_nan_int_setup6(mt_desc_t desc, nan_int_setup6_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // fill response with correct values

  // !!! notify controller that setup is complete
  return 0;
}



/**************************** Nano Direct Pay ***************************/

static int handle_nan_int_direct2(mt_desc_t desc, nan_int_direct2_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // fill response with correct values

  // !!! notify controller that direct pay is complete
  return 0;
}

/**************************** Nano Establish ****************************/

static int handle_nan_rel_estab6(mt_desc_t desc, nan_rel_estab6_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // fill response with correct values

  // !!! notify controller that establish is complete
  return 0;
}

/******************************* Nano Pay *******************************/

static int handle_nan_rel_pay2(mt_desc_t desc, nan_rel_pay2_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // fill response with correct values

  // !!! notify controller that pay is complete
  return 0;
}


/******************************* Nano Close *****************************/

static int handle_nan_int_close2(mt_desc_t desc, nan_int_close2_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  nan_end_close3_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_nan_end_close3(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE3, resp_msg, resp_size);

  return 0;
}

static int handle_nan_int_close4(mt_desc_t desc, nan_int_close4_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  nan_end_close5_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_nan_end_close5(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE5, resp_msg, resp_size);

  return 0;
}

static int handle_nan_int_close6(mt_desc_t desc, nan_int_close6_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  nan_end_close7_t response;

  // fill response with correct values

  byte* resp_msg;
  int resp_size = pack_nan_end_close7(response, &client.pk, &client.sk,  &resp_msg);
  mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE7, resp_msg, resp_size);

return 0;
}

static int handle_nan_int_close8(mt_desc_t desc, nan_int_close8_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // fill response with correct values

  // !!! notify controller that close is complete

  return 0;
}

/******************************* Ledger Queries *************************/

static int handle_mac_led_data(mt_desc_t desc, mac_led_data_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // fill response with correct values

  // !!! notify controller that query is complete

  return 0;
}

static int handle_chn_led_data(mt_desc_t desc, chn_led_data_t* token, byte (*pk)[MT_SZ_PK]){
  (void)token;
  (void)pk;
  (void)desc;

  // check validity incoming message

  // fill response with correct values

  // !!! notify controller that query is complete
  return 0;
}

/***************************** Helper Functions *************************/

static int compare_chn_end_data(const void** a, const void** b){

  if(((mt_channel_t*)(*a))->data->balance > ((mt_channel_t*)(*b))->data->balance)
    return -1;

  if(((mt_channel_t*)(*a))->data->balance < ((mt_channel_t*)(*b))->data->balance)
    return 1;

  return 0;
}
