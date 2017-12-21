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
#include "buffers.h"

#define INTERMEDIARY_REACHABLE_NO 0
#define INTERMEDIARY_REACHABLE_YES 1
#define INTERMEDIARY_REACHABLE_MAYBE 2
#define INTERMEDIARY_MAX_RETRIES 3

#define INTERMEDIARY_COOKIE_LEN 16

typedef struct intermediary_t {
  intermediary_identity_t* identity;
  char nickname[MAX_HEX_NICKNAME_LEN+1];
  unsigned int is_reachable : 2;
  time_t chosen_at;
  extend_info_t *ei;
  /*Used by the payment module*/
  mt_desc_t desc;
  /*
   * Whether this intermediary is used
   * to pay for middle or exit
   */
  position_t linked_to;
  /* how many times we try to build a circuit
   * with that intermediary */
  uint32_t circuit_retries;

  /*buffer payment cells received by this intermediary
   *if we get multiple cells for one mt_ntype_t */
  buf_t *buf;

} intermediary_t;

/**
 * Convert a mt public key into an mt address
 */
int mt_pk2addr(byte (*pk)[MT_SZ_PK], byte (*addr_out)[MT_SZ_ADDR]);

/**
 * Convert a moneTor descriptor into a digest for digestmap_t
 */
void mt_desc2digest(mt_desc_t* desc, byte (*digest_out)[DIGEST_LEN]);

/**
 * Convert a moneTor nan_any_public_t into a digest for digestmap_t
 */
void mt_nanpub2digest(nan_any_public_t* token, byte (*digest_out)[DIGEST_LEN]);

/**
 * Convert an mt address into a printable hexidecimal c-string
 */
int mt_bytes2hex(byte* bytes, int size, char** hex_out);

/**
 * Converts a hex digest (c-string) into a malloc'd byte string
 */
int mt_hex2bytes(char* hex, byte** bytes_out);

/**
 * Create malloc'd hash chain of the given size using the given head
 */
int mt_hc_create(int size, byte (*head)[MT_SZ_HASH], byte (*hc_out)[][MT_SZ_HASH]);

/**
 * Verify that a given preimage is indeed the kth preimage of the
 * given hash chain tail
 */
int mt_hc_verify(byte (*tail)[MT_SZ_HASH], byte (*preimage)[MT_SZ_HASH], int k);

int mt_commit_wallet(byte (*pp)[MT_SZ_PP], byte (*pk)[MT_SZ_PK], chn_end_secret_t* chn, int epislon);

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


/**
 * Pack the relay header containing classical relay_header_t
 * and our payment header
 */
void relay_pheader_pack(uint8_t *dest, const relay_header_t* rh,
    relay_pheader_t* rph);


/** Unpack the network order buffer src into relay_pheader_t
 * struct
 */
void relay_pheader_unpack(relay_pheader_t *desc, const uint8_t *src);


void direct_pheader_pack(uint8_t *dest, relay_pheader_t *rph);

/**
 * gives a string description of this mt_desc_t*
 */
const char* mt_desc_describe(mt_desc_t *desc);


/** Interface to the payment module to send a payment cell.
 *  This function dispaches to the right controller.
 */
MOCK_DECL(void, mt_process_received_relaycell, (circuit_t *circ, relay_header_t* rh,
    relay_pheader_t *rph, crypt_path_t* layer_hint, uint8_t* payload));

/** Interface to the payment module
 * Dispatches to client controller or Intermediary controller
 */

int mt_process_received_directpaymentcell(circuit_t *circ, cell_t *cell);

/************ Tor - Payment event interface *********************/

/**
 * Send a message to the given descriptor
 */
MOCK_DECL(int, mt_send_message, (mt_desc_t *desc, mt_ntype_t type, byte* msg, int size));

/**
 * Send a message to the given descriptor attaching info about a 2nd descriptor
 */
MOCK_DECL(int, mt_send_message_multidesc, (mt_desc_t *desc1, mt_desc_t* desc2, mt_ntype_t type, byte* msg, int size));

/**
 * Alert the relay controller that a payment was received by the specified client
 */
MOCK_DECL(int, mt_alert_payment, (mt_desc_t *desc));

/**
 * Inform the controller of the success of an mt_cpay_pay() protocol
 */
MOCK_DECL(int, mt_pay_success, (mt_desc_t *rdesc, mt_desc_t* idesc, int success));

/**
 * Inform the controller of the success of an mt_cpay_close() protocol
 */
MOCK_DECL(int, mt_close_success, (mt_desc_t *rdesc, mt_desc_t* idesc, int success));



#endif
