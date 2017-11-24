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
 * Single instance of a relay payment object
 */
typedef struct {

    byte pp[MT_SZ_PP];
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];
    byte addr[MT_SZ_ADDR];

    smartlist_t* chns_open;
    digestmap_t* chns_taken;

} mt_rpay_t;

/**
 * Initialize a relay instance given public parameters, a currency
 * keypair, and a list of channels associated with the keypair.
 */
int mt_rpay_init(mt_rpay_t* relay, byte (*pp)[MT_SZ_PP], byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK],
		   chn_end_data_t* chn_data, int num_chns);

/**
 * Handle a special establish init message. This is needed because unlike other
 * messages, we need to consider not one but two descriptors
 */
int mt_cpay_recvestab(mt_desc_t relay, mt_desc_t intermediary, byte* msg, int size);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_rpay_recv_message(mt_rpay_t* relay, mt_desc_t desc, mt_ntype_t type, byte* msg, int size);

#endif
