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

#endif
