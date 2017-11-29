/**
 * \file mt_rpay.h
 * \brief Header file for mt_rpay.c
 **/

#ifndef mt_rpay_h
#define mt_rpay_h

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"

/**
 * Initialize a relay instance given public parameters, a currency
 * keypair, and a list of channels associated with the keypair.
 */
int mt_rpay_init(void);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_rpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/**
 * Handle a special establish init message. This is needed because unlike other
 * messages, we need to consider not one but two descriptors
 */
int mt_rpay_recv_multidesc(mt_desc_t* client, mt_desc_t* intermediary, mt_ntype_t type, byte* msg, int size);

/**
 * Notify the payment module that a descriptor connection is read
 */
int mt_rpay_notify_connect(mt_desc_t* desc);

#endif
