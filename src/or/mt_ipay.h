/**
 * \file mt_ipay.h
 * \brief Header file for mt_ipay.c
 **/

#ifndef mt_ipay_h
#define mt_ipay_h

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_ipay.h"

/**
 * Single instance of an intermediary payment object
 */
typedef struct {

    byte pp[MT_SZ_PP];
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];
    byte addr[MT_SZ_ADDR];

    smartlist_t* chns_open;
    digestmap_t* chns_taken;

} mt_ipay_t;

/**
 * Initialize a intermediary instance given public parameters, a currency
 * keypair, and a list of channels associated with the keypair.
 */
int mt_ipay_init(mt_ipay_t* intermediary, byte (*pp)[MT_SZ_PP], byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK],
		   chn_end_data_t* chn_data, int num_chns);

/**
 * Cashout of a payment channel
 */
int mt_ipay_cashout(mt_ipay_t* intermediary, byte (*chn_addrs)[MT_SZ_ADDR]);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_ipay_recv_cells(mt_ipay_t* intermediary, mt_desc_t desc, mt_ntype_t type, byte** msg, int size);


/*************** Should probably be in controller? **********/

int node_is_intermediary(const node_t *node);

#endif
