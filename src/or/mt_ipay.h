/**
 * \file mt_ipay.h
 * \brief Header file for mt_ipay.c
 **/

#ifndef mt_ipay_h
#define mt_ipay_h

#include "or.h"

/**
 * Initialize the intermediary payment module
 */
int mt_ipay_init(void);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_ipay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

#endif
