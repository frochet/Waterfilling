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
 * Single instance of a client payment object
 */
typedef struct {

    byte pp[MT_SZ_PP];
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];
    byte addr[MT_SZ_ADDR];

    smartlist_t* chns_open;
    digestmap_t* chns_taken;

} mt_cpay_t;

/**
 * Initialize a client instance given public parameters, a currency
 * keypair, and a list of channels associated with the keypair.
 */
int mt_cpay_init(mt_cpay_t* client, byte (*pp)[MT_SZ_PP], byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK],
		   chn_end_data_t* chn_data, int num_chns);

/**
 * Establish a nanopayment channel with the given descriptor
 */
int mt_cpay_establish(mt_cpay_t* client, mt_desc_t desc);

/**
 * Pay the given descriptor using an existing nanopayment channel
 */
int mt_cpay_pay(mt_cpay_t* client, mt_desc_t desc);

/**
 * Close a nanopayment channel with the given descriptor
 */
int mt_cpay_close(mt_cpay_t* client, mt_desc_t desc);

/**
 * Cashout of a payment channel
 */
int mt_cpay_cashout(mt_cpay_t* client, byte (*chn_addrs)[MT_SZ_ADDR]);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_cpay_recv_cells(mt_cpay_t* client, mt_desc_t desc, mt_ntype_t type, byte** msg, int size);

/*************** Should probably be in controller? **********/


//handle intermediaries
//XXX MoneTor maybe all of intermediary-handling
//    function need to be in a separate file?

smartlist_t* get_intermediaries(int for_circuit);
/**
 * Picks a random intermediary from our pre-built list
 * of available intermediaries
 */
const node_t* choose_random_intermediary(void);
/**
 * XXX MoneTor edge_connection_t* should have some information
 * about the payment channel that is used with that intermediary
 * or does not if this is a fresh payment channel
 */
extend_info_t* mt_cpay_get_intermediary_from_edge(edge_connection_t* conn);

/**
 * Parse the state file to get the intermediaries we were using before
 *
 * NOT URGENT
 */
int intermediary_parse_state(or_state_t *state, int set, char** msg);
#endif
