/**
 * \file mt_tokens.h
 * \brief Header file for mt_tokens.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_cpay_h
#define mt_cpay_h

#include "or.h"

/**
 * Initialize a client instance given public parameters, a currency
 * keypair, and a list of channels associated with the keypair.
 */
int mt_cpay_init(void);

/**
 * Pay the given descriptor directly (instead of through an intermediary) as
 * needed for paying entry guards
 */
int mt_cpay_directpay(mt_desc_t* desc);

/**
 * Pay the given descriptor using an existing nanopayment channel
 */
int mt_cpay_pay(mt_desc_t* desc);

/**
 * Close a nanopayment channel with the given descriptor
 */
int mt_cpay_close(mt_desc_t* desc);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_cpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/************************ Needs to be moved somewhere else *******/

// common
void mt_desc2digest(mt_desc_t* desc, byte (*digest_out)[DIGEST_LEN]);

#endif
