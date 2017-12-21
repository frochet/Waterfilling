/**
 * \file mt_common.c
 *
 * General purpose module that houses basic useful functionality for various
 * users of the moneTor payment scheme. This module will be likely updated
 * frequently as the scheme is expanded
 */

#pragma GCC diagnostic ignored "-Wswitch-enum"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "or.h"
#include "buffers.h"
#include "config.h"
#include "compat.h"
#include "circuituse.h"
#include "mt_crypto.h" // only needed for the defined byte array sizes
#include "mt_common.h"
#include "mt_cclient.h"
#include "mt_crelay.h"
#include "mt_cintermediary.h"
#include "mt_tokens.h"
#include "router.h"

/**
 * Converts a public key into an address for use on the ledger. The address is
 * generated by a simple hash of the public key and is 20 bytes long.
 */
int mt_pk2addr(byte (*pk)[MT_SZ_PK], byte (*addr_out)[MT_SZ_ADDR]){
  byte hash[MT_SZ_HASH];
  mt_crypt_hash(*pk, MT_SZ_PK, &hash);
  memcpy(*addr_out, hash, MT_SZ_ADDR);
  return MT_SUCCESS;
}

/**
 * Converts an mt_desc_t into an address for use in digestmaps. The output is
 * a hash of the mt_desc_t contents truncated to 20 bytes
 */
void mt_desc2digest(mt_desc_t* desc, byte (*digest_out)[DIGEST_LEN]){
  byte hash[MT_SZ_HASH];
  byte input[sizeof(uint32_t) + sizeof(desc->party)];
  memcpy(input, &desc->id, sizeof(uint32_t));
  memcpy(input + sizeof(uint32_t), &desc->party, sizeof(desc->party));
  mt_crypt_hash(input, sizeof(uint32_t) + sizeof(desc->party), &hash);
  memcpy(*digest_out, hash, DIGEST_LEN);
}

/**
 * Convert a moneTor nan_any_public_t into a digest for digestmap_t
 */
void mt_nanpub2digest(nan_any_public_t* token, byte (*digest_out)[DIGEST_LEN]){
  byte hash[MT_SZ_HASH];
  byte input[sizeof(int) * 3 + MT_SZ_HASH];
  memcpy(input + sizeof(int) * 0, &token->val_from, sizeof(int));
  memcpy(input + sizeof(int) * 1, &token->val_to, sizeof(int));
  memcpy(input + sizeof(int) * 2, &token->num_payments, sizeof(int));
  memcpy(input + sizeof(int) * 3, &token->hash_tail, MT_SZ_HASH);
  mt_crypt_hash(input, sizeof(int) * 3 + MT_SZ_HASH, &hash);
  memcpy(*digest_out, hash, DIGEST_LEN);
}


/**
 * Converts an address in byte-string form to a more human-readable hexadecimal
 * string. The format is in the style of Ethereum as it leads with the '0x'
 */
int mt_addr2hex(byte (*addr)[MT_SZ_ADDR], char (*hex_out)[MT_SZ_ADDR * 2 + 3]){

  (*hex_out)[0] = '0';
  (*hex_out)[1] = 'x';

  for(int i = 0; i < MT_SZ_ADDR; i++)
    sprintf(&((*hex_out)[i*2 + 2]), "%02X", (*addr)[i]);

  (*hex_out)[MT_SZ_ADDR * 2 + 2] = '\0';
  return MT_SUCCESS;
}

/**
 * Compute a hash chain of the given size using the given random head. The
 * output is written to the inputted hc_out address, which is a pointer to a
 * arbitrary sized array of pointers to MT_SZ_HASH arrays. The ordering is such
 * that the tail of the chain is at the front of the array and the head is at
 * the rear.
 */
int mt_hc_create(int size, byte (*head)[MT_SZ_HASH], byte (*hc_out)[][MT_SZ_HASH]){
  if(size < 1)
    return MT_ERROR;

  memcpy(&((*hc_out)[size -1]), *head, MT_SZ_HASH);	\

    for(int i = size - 2; i >= 0; i--){
      if(mt_crypt_hash((*hc_out)[i+1], MT_SZ_HASH, &((*hc_out)[i])) != MT_SUCCESS)
        return MT_ERROR;
    }
  return MT_SUCCESS;
}

/**
 * Verifies the claim that a given preimage is in fact the kth element on a hash
 * chain starting at the given tail.
 */
int mt_hc_verify(byte (*tail)[MT_SZ_HASH], byte (*preimage)[MT_SZ_HASH], int k){
  byte current[MT_SZ_HASH];
  byte temp[MT_SZ_HASH];

  memcpy(current, *preimage, MT_SZ_HASH);
  for(int i = 0; i < k; i++){
    if(mt_crypt_hash(current, MT_SZ_HASH, &temp) != MT_SUCCESS)
      return MT_ERROR;
    memcpy(current, temp, MT_SZ_HASH);
  }

  if(memcmp(current, *tail, MT_SZ_HASH) != 0)
    return MT_ERROR;

  return MT_SUCCESS;
}

/*
 * Should be called by the tor_init() function - initialize all environment
 * for the payment system
 *
 * XXX MoneTor to do regardless of the role played.
 */
void mt_init(void){
  log_info(LD_MT, "MoneTor: Initializing the payment system");
  mt_cclient_init();
  /* Todo call intermediary, relay and ledger init? */

}

/**
 * Verifies enough money remains in the wallet - NOT URGENT
 */
int mt_check_enough_fund(void) {
  return 1;
}

/**
 * Run scheduled events of the payment systems. Get called every second and
 * verifies that everything holds.
 * TODO : - check healthiness of intermediary circuit, consider cacshout?, etc?
 */
void monetor_run_scheduled_events(time_t now) {

  /*run scheduled cclient event - avoid to do this on authority*/
  run_cclient_scheduled_events(now);

  /*XXX MoneTor - Todo: adding scheduled events for intermediaries, relays, etc */

}

/**
 * Returns a description of this desc. Mostly used for log
 * purpose
 *
 * XXX MoneTor Todo
 */

const char* mt_desc_describe(mt_desc_t* desc) {
  (void) desc;
  return "";
}

/** Free mt_desc */
void mt_desc_free(mt_desc_t *desc) {
  if (!desc)
    return;
  // XXX todo
}

/**
 * Pack the relay header containing classical relay_header_t
 * and our payment header
 */

void relay_pheader_pack(uint8_t *dest, const relay_header_t* rh,
    relay_pheader_t* rph) {
  set_uint8(dest, rh->command);
  set_uint16(dest+1, htons(rh->recognized));
  set_uint16(dest+3, htons(rh->stream_id));
  memcpy(dest+5, rh->integrity, 4);
  set_uint16(dest+9, htons(rh->length));
  set_uint8(dest+10, rph->pcommand);
}

/** Unpack the network order buffer src into relay_pheader_t
 * struct
 */
void relay_pheader_unpack(relay_pheader_t *dest, const uint8_t *src) {
  dest->pcommand = get_uint8(src);
  dest->length = ntohs(get_uint16(src+1));
}

void direct_pheader_pack(uint8_t *dest, relay_pheader_t *rph) {
  set_uint8(dest, rph->pcommand);
  set_uint16(dest+1, htons(rph->length));
}  

/** Called when we get a MoneTor cell on circuit circ.
 *  gets the right mt_desc_t and dispatch to the right
 *  payment module
 *
 *  layer_hint allows us to know which relay sent us this cell
 */

MOCK_IMPL(void,
    mt_process_received_relaycell, (circuit_t *circ, relay_header_t* rh,
    relay_pheader_t* rph, crypt_path_t *layer_hint, uint8_t* payload)) {
  (void) rh; //need to refactor
  size_t msg_len = mt_token_get_size_of(rph->pcommand);
  if (authdir_mode(get_options())) {
  }
  else if (intermediary_mode(get_options())) {
    if (CIRCUIT_IS_ORCIRC(circ)) {
      // should be circuit built towards us by a client or
      // a relay
      or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
      /** It is a payment cell over a or-circuit - should be
       * sent a client or a relay - change purpose */
      if (circ->purpose == CIRCUIT_PURPOSE_OR) {
        // Should be done at the first received payment cell
        // over this circuit
        circuit_change_purpose(circ, CIRCUIT_PURPOSE_INTERMEDIARY);
        TO_OR_CIRCUIT(circ)->buf = buf_new_with_capacity(RELAY_PPAYLOAD_SIZE);
        mt_cintermediary_init_desc_and_add(orcirc);
      }
      /*buffer data if necessary*/
      if (msg_len > RELAY_PPAYLOAD_SIZE) {
        buf_add(orcirc->buf, (char*) payload, rph->length);
        if (buf_datalen(orcirc->buf) == msg_len) {
          /** We now have the full message */
          byte *msg = tor_malloc(msg_len);
          buf_get_bytes(orcirc->buf, (char*) msg, msg_len);
          buf_clear(orcirc->buf);
          mt_cintermediary_process_received_msg(circ, rph->pcommand, msg, msg_len);
          tor_free(msg);
        }
        else {
          log_info(LD_MT, "Buffering one received payment cell of type %hhx"
              " current buf datlen %lu", rph->pcommand, buf_datalen(orcirc->buf));
          return;
        }
      }
      else {
        /** No need to buffer */
        tor_assert(rph->length == msg_len);
        mt_cintermediary_process_received_msg(circ, rph->pcommand, payload,
            rph->length);
      }
    } 
    else if (CIRCUIT_IS_ORIGIN(circ)) {
      // should be a ledger circuit
      if (msg_len > RELAY_PPAYLOAD_SIZE) {
        ledger_t *ledger = mt_cintermediary_get_ledger();
        tor_assert(ledger);
        buf_add(ledger->buf, (char*) payload, rph->length);
        if (buf_datalen(ledger->buf) == msg_len) {
          byte *msg = tor_malloc(msg_len);
          buf_get_bytes(ledger->buf, (char*) msg, msg_len);
          buf_clear(ledger->buf);
          mt_cintermediary_process_received_msg(circ, rph->pcommand, msg, msg_len);
          tor_free(msg);
        }
        else {
          log_info(LD_MT, "Buffering one received payment cell of type %hhx"
              " current buf datlen %lu", rph->pcommand, buf_datalen(ledger->buf));
          return;
        }
      }
      else {
        /** No need to buffer */
        tor_assert(rph->length == msg_len);
        mt_cintermediary_process_received_msg(circ, rph->pcommand, payload,
            rph->length);
      }
    }
  }
  else if (server_mode(get_options())) {

  }
  else {
    /* Client mode with one origin circuit */
    if (CIRCUIT_IS_ORIGIN(circ)) {
      if (msg_len > RELAY_PPAYLOAD_SIZE) {
        if (circ->purpose == CIRCUIT_PURPOSE_C_GENERAL) {
          // get right ppath
          origin_circuit_t *ocirc = TO_ORIGIN_CIRCUIT(circ);
          pay_path_t *ppath = ocirc->ppath;
          crypt_path_t *cpath = ocirc->cpath;
          do {
            cpath = cpath->next;
            ppath = ppath->next;
          } while (cpath != layer_hint);
          /* We have the right hop  -- get the buffer */
          buf_add(ppath->buf, (char*) payload, rph->length);
          if (buf_datalen(ppath->buf) == msg_len) {
            /*We can now process the received message*/
            byte *msg = tor_malloc(msg_len);
            buf_get_bytes(ppath->buf, (char*) msg, msg_len);
            buf_clear(ppath->buf);
            mt_cclient_process_received_msg(ocirc, layer_hint, rph->pcommand, msg, msg_len);
            tor_free(msg);
          }
          else {
            log_info(LD_MT, "Buffering one received payment cell of type %hhx"
                " current buf datalen: %lu", rph->pcommand, buf_datalen(ppath->buf));
            return;
          }
        }
        else if (circ->purpose == CIRCUIT_PURPOSE_C_INTERMEDIARY) {
          origin_circuit_t *ocirc = TO_ORIGIN_CIRCUIT(circ);
          intermediary_t *intermediary = mt_cclient_get_intermediary_from_ocirc(ocirc);
          buf_add(intermediary->buf, (char*) payload, rph->length);
          if (buf_datalen(intermediary->buf) == msg_len) {
            byte *msg = tor_malloc(msg_len);
            buf_get_bytes(intermediary->buf, (char*) msg, msg_len);
            buf_clear(intermediary->buf);
            mt_cclient_process_received_msg(ocirc, layer_hint, rph->pcommand, msg, msg_len);
            tor_free(msg);
          }
          else {
            log_info(LD_MT, "Buffering one received payment cell of type %hhx"
                " current buf datalen on the intermediary: %lu",
                rph->pcommand, buf_datalen(intermediary->buf));
            return;
          }
        }
        else {
          // XXX ledger stuff
        }
      }
      else {
        /* Yay no need to buffer */
        tor_assert(rph->length == msg_len);
        mt_cclient_process_received_msg(TO_ORIGIN_CIRCUIT(circ), layer_hint, rph->pcommand,
            payload, rph->length);
      }
    }
    else {
      /* defensive prog */
      log_warn(LD_MT, "Receiving a client payment cell on a non-origin circuit. dafuk?");
      return;
    }
  }
}

/*
 * Called when we got a peer-level MoneTor cell on this circ. No onion-decryption
 * had to be performed.  cell must contain the plaintext 
 */

int mt_process_received_directpaymentcell(circuit_t *circ, cell_t *cell) {
  
  relay_pheader_t rph;
  relay_pheader_unpack(&rph, cell->payload);

  if (server_mode(get_options())) {
  }
  else {
    /* Should in client mode with an origin circuit */
    if (CIRCUIT_IS_ORIGIN(circ)) {
      /* everything's ok, let's proceed */

      mt_cclient_process_received_directpaymentcell(TO_ORIGIN_CIRCUIT(circ), cell, &rph);
    }
    else {
      return -1;
    }
  }
  /* if we reach this, everything is ok */
  return 0;
}

/** Interface to the payment module to send a payment cell.
 *  This function dispaches to the right controller.
 */

MOCK_IMPL(int, mt_send_message, (mt_desc_t *desc, mt_ntype_t type,
      byte* msg, int size)) {

  switch (type) {
    uint8_t command;
    /* sending Client related message */
    case MT_NTYPE_NAN_CLI_DESTAB1:
    case MT_NTYPE_NAN_CLI_DPAY1:
      command = CELL_PAYMENT;
      return mt_cclient_send_message(desc, command, type, msg, size);
    case MT_NTYPE_MIC_CLI_PAY1:
    case MT_NTYPE_MIC_CLI_PAY3:
    case MT_NTYPE_MIC_CLI_PAY5:
    case MT_NTYPE_NAN_CLI_SETUP1:
    case MT_NTYPE_NAN_CLI_SETUP3:
    case MT_NTYPE_NAN_CLI_SETUP5:
    case MT_NTYPE_NAN_CLI_ESTAB1:
    case MT_NTYPE_NAN_CLI_PAY1:
    case MT_NTYPE_NAN_CLI_REQCLOSE1:
      command = RELAY_COMMAND_MT;
      return mt_cclient_send_message(desc, command, type, msg, size);
    /* Sending relay related message */
    case MT_NTYPE_MIC_REL_PAY2:
    case MT_NTYPE_MIC_REL_PAY6:
    case MT_NTYPE_NAN_REL_ESTAB2:
    case MT_NTYPE_NAN_REL_ESTAB4:
    case MT_NTYPE_NAN_REL_ESTAB6:
    case MT_NTYPE_NAN_REL_PAY2:
    case MT_NTYPE_NAN_REL_REQCLOSE2:
      command = RELAY_COMMAND_MT;
      return mt_crelay_send_message(desc, command, type, msg, size);
    /* Sending to intermediary from client or server */
    case MT_NTYPE_CHN_END_ESTAB1:
    case MT_NTYPE_CHN_END_ESTAB3:
    case MT_NTYPE_NAN_END_CLOSE1:
    case MT_NTYPE_NAN_END_CLOSE3:
    case MT_NTYPE_NAN_END_CLOSE5:
    case MT_NTYPE_NAN_END_CLOSE7:
    case MT_NTYPE_CHN_END_SETUP:
    case MT_NTYPE_CHN_END_CLOSE:
    case MT_NTYPE_CHN_END_CASHOUT:
      command = RELAY_COMMAND_MT;
      /* check server mode*/
      if (server_mode(get_options())) {
        return mt_crelay_send_message(desc, command, type, msg, size);
      }
      else {
        return mt_cclient_send_message(desc, command, type, msg, size);
      }
    /* Sending from authority */
    case MT_NTYPE_MAC_AUT_MINT:
      if (authdir_mode(get_options())) {
        // XXX Todo new file related to authdir
        return 0;
      }
      break;
    /* Sending from intermediary */
    case MT_NTYPE_CHN_INT_ESTAB2:
    case MT_NTYPE_CHN_INT_ESTAB4:
    case MT_NTYPE_MIC_INT_PAY4:
    case MT_NTYPE_MIC_INT_PAY7:
    case MT_NTYPE_MIC_INT_PAY8:
    case MT_NTYPE_NAN_INT_SETUP2:
    case MT_NTYPE_NAN_INT_SETUP4:
    case MT_NTYPE_NAN_INT_SETUP6:
    case MT_NTYPE_NAN_INT_DESTAB2:
    case MT_NTYPE_NAN_INT_DPAY2:
    case MT_NTYPE_NAN_INT_CLOSE2:
    case MT_NTYPE_NAN_INT_CLOSE4:
    case MT_NTYPE_NAN_INT_CLOSE6:
    case MT_NTYPE_NAN_INT_CLOSE8:
    case MT_NTYPE_NAN_INT_ESTAB3:
    case MT_NTYPE_NAN_INT_ESTAB5:
    case MT_NTYPE_CHN_INT_SETUP:
    case MT_NTYPE_CHN_INT_CLOSE:
    case MT_NTYPE_CHN_INT_REQCLOSE:
    case MT_NTYPE_CHN_INT_CASHOUT:
      if (intermediary_mode(get_options())) {
        command = RELAY_COMMAND_MT;
        //todo
        return 0;
      }
      else if (server_mode(get_options())) {
        /* Should match Direct payments */
        command = CELL_PAYMENT;
        // todo
        return 0;
      }
      else {
        log_warn(LD_MT, "Cannot handle type %d", (uint8_t)type);
      }
      break;
      /* Sending from any of them */
    case MT_NTYPE_MAC_ANY_TRANS:
      command = RELAY_COMMAND_MT;
      if (intermediary_mode(get_options())) {
        return 0;
      }
      else if (server_mode(get_options())) {
        return mt_crelay_send_message(desc, command, type, msg, size);
      }
      else if (authdir_mode(get_options())) {
        return 0;
      }
      else {
        return mt_cclient_send_message(desc, command, type, msg, size);
      }

    default:
      log_warn(LD_MT, "MoneTor - Unrecognized type");
      return -1;
  }
  return -1;
}

MOCK_IMPL(int, mt_send_message_multidesc, (mt_desc_t *desc1, mt_desc_t* desc2, mt_ntype_t type, byte* msg, int size)) {
  (void) desc1;
  (void) desc2;
  (void) type;
  (void) msg;
  (void) size;
  return 0;
}

MOCK_IMPL(int, mt_alert_payment, (mt_desc_t *desc)) {
  (void) desc;
  return 0;
}

MOCK_IMPL(int, mt_pay_success, (mt_desc_t *rdesc, mt_desc_t* idesc, int success)){
  (void)rdesc;
  (void)idesc;
  (void)success;
  return 0;
}

MOCK_IMPL(int, mt_close_success, (mt_desc_t *rdesc, mt_desc_t* idesc, int success)){
  (void)rdesc;
  (void)idesc;
  (void)success;
  return 0;
}
