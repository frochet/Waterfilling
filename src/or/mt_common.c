/**
 * \file mt_common.c
 *
 * General purpose module that houses basic useful functionality for various
 * users of the moneTor payment scheme. This module will be likely updated
 * frequently as the scheme is expanded
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mt_crypto.h" // only needed for the defined byte array sizes
#include "mt_common.h"
#include "mt_cclient.h"
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
  //printf("%x", *((uint32_t*)input);
  memcpy(input + sizeof(uint32_t), &desc->party, sizeof(desc->party));
  mt_crypt_hash(input, sizeof(desc), &hash);
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

  /*Todo: adding scheduled events for intermediaries, relays, etc */

}

MOCK_IMPL(int, mt_send_message, (mt_desc_t *desc, mt_ntype_t type, byte* msg, int size)) {
  (void) desc;
  (void) type;
  (void) msg;
  (void) size;
  return 0;
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

MOCK_IMPL(int, mt_new_intermediary, (mt_desc_t *desc)){
  (void) desc;
  return 0;
}