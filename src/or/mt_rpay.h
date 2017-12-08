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
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_rpay_init(void);

/**
 * Handle an incoming message from the given descriptor
 */
int mt_rpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/**
 * Handle an incoming message from the given client descriptor that is also
 * associated with a new intermediary descriptor. Currently, this is only needed
 * for the singular nan_cli_estab1 message.
 */
int mt_rpay_recv_multidesc(mt_desc_t* cdesc, mt_desc_t* idesc, mt_ntype_t type, byte* msg, int size);

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_rpay_mac_balance(void);

/**
 * Return the balance of money locked up in channels
 */
int mt_rpay_chn_balance(void);


#endif
