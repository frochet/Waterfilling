/**
 * \file mt_common.h
 * \brief Header file for mt_common.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_common_h
#define mt_common_h

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"



typedef enum {
  MIDDLE,
  EXIT,
} position_t;

#define INTERMEDIARY_REACHABLE_NO 0
#define INTERMEDIARY_REACHABLE_YES 1
#define INTERMEDIARY_REACHABLE_MAYBE 2


typedef struct intermediary_t {
  intermediary_identity_t* identity;
  char nickname[MAX_HEX_NICKNAME_LEN+1];
  unsigned int is_reachable : 2;
  time_t chosen_at;
  extend_info_t *ei;
  // TD: doesn't compile, is this supposed to be my_dest_t?
  // FR: yup - typos
  mt_desc_t *m_channel;
  /*
   * Whether this intermediary is used
   * to pay for middle or exit
   */
  position_t linked_to;
  /* how many times we try to build a circuit
   * with that intermediary */
  uint32_t circuit_retries;
} intermediary_t;

/**
 * Convert a mt public key into an mt address
 */
int mt_pk2addr(byte (*pk)[MT_SZ_PK], byte (*addr_out)[MT_SZ_ADDR]);

/**
 * Convert an mt address into a printable hexidecimal c-string
 */
int mt_addr2hex(byte (*addr)[MT_SZ_ADDR], char (*hex_out)[MT_SZ_ADDR * 2 + 3]);

/**
 * Create malloc'd hash chain of the given size using the given head
 */
int mt_hc_create(int size, byte (*head)[MT_SZ_HASH], byte (*hc_out)[][MT_SZ_HASH]);

/**
 * Verify that a given preimage is indeed the kth preimage of the
 * given hash chain tail
 */
int mt_hc_verify(byte (*tail)[MT_SZ_HASH], byte (*preimage)[MT_SZ_HASH], int k);

/** Canibalize a general circuit => extends it to
 *  the intermediary point described by ei
 *
 *  ret 0 on success
 */
int mt_circuit_launch_intermediary(extend_info_t* ei);

/** Callback function called when an intermediary
 *  circuit is open
 */
void mt_circuit_intermediary_has_opened(origin_circuit_t* circuit);

void mt_init(void);

/**
 * Has enough funds to pay for prioritization? returns 1 or 0
 */
int mt_check_enough_fund(void);

/**
 * gets called by the main loop every second.
 */
void monetor_run_scheduled_events(time_t now);


/************ Tor - Payment event interface *********************/

int send_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size);

int alert_payment(mt_desc_t *desc);

#endif
