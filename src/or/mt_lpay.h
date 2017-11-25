/**
 * \file mt_lpay.h
 * \brief Header file for mt_lpay.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_lpay_h
#define mt_lpay_h

#include "or.h"

#define MT_FEE 5
#define MT_TAX 5
#define MT_CLOSEWINDOW 5

/**
 * Initialize a ledger instance given public input parameters
 * <b>pp<\b>, a per-ledger-post fee <b>fee<\b>, an intermediary tax
 * <b>tax<\b>, the number of epochs allowed for counterparties to
 * close a channel <b>close_window<\b>, and the public key of the tor
 * tax collector authority <b>auth_pk<\b>
 */
int mt_lpay_init(void);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_lpay_recv_message(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

#endif
