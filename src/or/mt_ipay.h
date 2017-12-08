/**
 * \file mt_ipay.h
 * \brief Header file for mt_ipay.c
 **/

#ifndef mt_ipay_h
#define mt_ipay_h

#include "or.h"

/**
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_ipay_init(void);

/**
 * Handle an incoming message from the given descriptor
 */
int mt_ipay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_ipay_mac_balance(void);

/**
 * Return the balance of money locked up in channels
 */
int mt_ipay_chn_balance(void);


#endif
