/**
 * \file mt_lpay.h
 * \brief Header file for mt_lpay.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_lpay_h
#define mt_lpay_h

#include "or.h"

/**
 * Single instance of a ledger payment object.
 */
typedef struct {

    digestmap_t* mac_accounts;
    digestmap_t* chn_accounts;

    byte pp[MT_SZ_PP];
    int fee;
    double tax;
    int epoch;
    int close_window;

    byte auth_addr[MT_SZ_ADDR];
    byte led_pk[MT_SZ_PK];
    byte led_sk[MT_SZ_SK];
    byte led_addr[MT_SZ_ADDR];

} mt_lpay_t;

/**
 * Initialize a ledger instance given public input parameters
 * <b>pp<\b>, a per-ledger-post fee <b>fee<\b>, an intermediary tax
 * <b>tax<\b>, the number of epochs allowed for counterparties to
 * close a channel <b>close_window<\b>, and the public key of the tor
 * tax collector authority <b>auth_pk<\b>
 */
int mt_lpay_init(mt_lpay_t* ledger, byte (*pp)[MT_SZ_PP], int fee,  double tax, int close_window, byte (*auth_pk)[MT_SZ_PK]);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_lpay_recv_message(mt_lpay_t* ledger, mt_desc_t desc, mt_ntype_t type, byte* msg, int size);

#endif
