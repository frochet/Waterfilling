/**
 * \file mt_ledger.c
 * \brief Implement a simple ledger for operating the moneTor payment
 * system. It most closely models the Ethereum ledger paradigm in which accounts
 * are maintained in the form of address->data pairings. This means that the
 * entire state of the system is immediately accessible at any time, which
 * stands in contrast to bitcoin model which keeps a permanent log of historical
 * events. The moneTor ledger currently recognizes two types of addresses:
 *
 *     Standard - Normal address owned by a user which can be used to transfer
 *     funds on the ledger
 *
 *     Channel - Special address that is used by two people to hold
 *     ledger-information about an open micropayment channel between the two
 *     parties. Channels are modeled as a simple state machine (states
 *     enumerated in chn_state) with some external information about balances
 *     and timeouts.
 *
 * The outward-facing interface for the ledger consist of two methods:
 *
 *     post() - Accepts a message to update the ledger state
 *     query() - Accepts a message to retrieve information about the ledger
 *
 * Unless otherwise noted, all functions return 0 for success or -1 for failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_common.h"
#include "mt_ledger.h"

//TODO change glib calls to Tor containers
//TODO move resolve to separate algs file
//TODO enforce nonce


// helper functions
int addr_compare(gconstpointer a, gconstpointer b);
int transfer(mt_ledger_t* ledger, int* bal_from, int* bal_to, int val_from, int val_to, int val_roger);
int close_channel(mt_ledger_t* ledger, chn_led_data_t* data);

// formal protocol algorithm to resolve disputes (this will replaced with algs call)
void resolve(byte (*pp)[MT_SZ_PP], chn_end_chntok_t T_E, chn_int_chntok_t T_I,
	     chn_end_close_t rc_E, chn_int_close_t rc_I, int* end_bal, int*  int_bal);

/**
 * Called at the system setup to create brand new ledger.
 */
int mt_ledger_init(mt_ledger_t* ledger, mt_send_cells send_cells, mt_close_conn close_conn,
		   byte (*pp)[MT_SZ_PP], int fee, double  tax,  int close_window,
		   byte (*roger_pk)[MT_SZ_PK]){

    ledger->send_cells = send_cells;
    ledger->close_conn = close_conn;

    // initialize state
    ledger->mac_accounts = g_tree_new((GCompareFunc) addr_compare);
    ledger->chn_accounts = g_tree_new((GCompareFunc) addr_compare);

    if(ledger->mac_accounts == NULL || ledger->chn_accounts == NULL)
	return MT_ERROR;

    // set ledger attributes
    memcpy(ledger->pp, pp, MT_SZ_PP);
    ledger->fee = fee;
    ledger->tax = tax;
    ledger->close_window = close_window;
    ledger->epoch = 0;

    // add roger's address as the first node in the state
    if(mt_pk2addr(roger_pk, &ledger->roger_addr) != MT_SUCCESS)
	return MT_ERROR;

    // generate ledger keys/address
    mt_crypt_keygen(&ledger->pp, &ledger->led_pk, &ledger->led_sk);
    if(mt_pk2addr(&ledger->led_pk, &ledger->led_addr) != MT_SUCCESS)
	return MT_ERROR;

    g_tree_insert(ledger->mac_accounts, ledger->roger_addr, calloc(1, sizeof(mac_led_data_t)));
    return MT_SUCCESS;
}

/**
 * Request to publish any type of information at all go to this function. The
 * function is responsible for parsing the message to interpret what should be
 * done with the request.
 */
int mt_ledger_recv_cells(mt_ledger_t* ledger, cell_t* cells, mt_desc_t desc) {

    //TODO need to aggregate cells... we're justing pretending they come it at once right now

    byte pk[MT_SZ_PK];
    byte addr[MT_SZ_ADDR];
    int result;

    switch(token_type(cells)){
	case MT_NTYPE_MAC_AUT_MINT:;
	    mac_aut_mint_t mac_aut_mint_tkn;
	    if(unpack_mac_aut_mint(cells, &mac_aut_mint_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_mac_aut_mint(ledger, &mac_aut_mint_tkn, &addr);
	    break;

	case MT_NTYPE_MAC_ANY_TRANS:;
	    mac_any_trans_t mac_any_trans_tkn;
	    if(unpack_mac_any_trans(cells, &mac_any_trans_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_mac_any_trans(ledger, &mac_any_trans_tkn, &addr);
	    break;

	case MT_NTYPE_CHN_END_ESCROW:;
	    chn_end_escrow_t chn_end_escrow_tkn;
	    if(unpack_chn_end_escrow(cells, &chn_end_escrow_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_end_escrow(ledger, &chn_end_escrow_tkn, &addr);
	    break;

	case MT_NTYPE_CHN_INT_ESCROW:;
	    chn_int_escrow_t chn_int_escrow_tkn;
	    if(unpack_chn_int_escrow(cells, &chn_int_escrow_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_int_escrow(ledger, &chn_int_escrow_tkn, &addr);
	    break;

	case MT_NTYPE_CHN_INT_REQCLOSE:;
	    chn_int_reqclose_t chn_int_reqclose_tkn;
	    if(unpack_chn_int_reqclose(cells, &chn_int_reqclose_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_int_reqclose(ledger, &chn_int_reqclose_tkn, &addr);
	    break;

	case MT_NTYPE_CHN_END_CLOSE:;
	    chn_end_close_t chn_end_close_tkn;
	    if(unpack_chn_end_close(cells, &chn_end_close_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_end_close(ledger, &chn_end_close_tkn, &addr);
	    break;

	case MT_NTYPE_CHN_INT_CLOSE:;
	    chn_int_close_t chn_int_close_tkn;
	    if(unpack_chn_int_close(cells, &chn_int_close_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_int_close(ledger, &chn_int_close_tkn, &addr);
	    break;

	case MT_NTYPE_CHN_END_CASHOUT:;
	    chn_end_cashout_t chn_end_cashout_tkn;
	    if(unpack_chn_end_cashout(cells, &chn_end_cashout_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_end_cashout(ledger, &chn_end_cashout_tkn, &addr);
	    break;

	case MT_NTYPE_CHN_INT_CASHOUT:;
	    chn_int_cashout_t chn_int_cashout_tkn;
	    if(unpack_chn_int_cashout(cells, &chn_int_cashout_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_int_cashout(ledger, &chn_int_cashout_tkn, &addr);
	    break;

	case MT_NTYPE_MAC_LED_QUERY:;
	    mac_led_query_t mac_led_query_tkn;
	    if(unpack_mac_led_query(cells, &mac_led_query_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_mac_led_query(ledger, &mac_led_query_tkn, desc);
	    break;

	case MT_NTYPE_CHN_LED_QUERY:;
	    chn_led_query_t chn_led_query_tkn;
	    if(unpack_chn_led_query(cells, &chn_led_query_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mt_pk2addr(&pk, &addr);
	    result = handle_chn_led_query(ledger, &chn_led_query_tkn, desc);
	    break;

	default:
	    result = MT_ERROR;
    }
    return result;
}

//---------------------------- Transaction Handler Functions ----------------------------//

/**
 * Mints the specified amount of new funds and adds it to roger's account.
 */
int handle_mac_aut_mint(mt_ledger_t* ledger, mac_aut_mint_t* token, byte (*addr)[MT_SZ_ADDR]){

    // make sure the message is signed by the ledger authority
    if(memcmp(ledger->roger_addr, addr, MT_SZ_ADDR) != 0)
	return MT_ERROR;

    // make sure value isn't negative for some reason
    if(token->value < 0)
	return MT_ERROR;

    // address is guaranteed to exist if module was setup with init()
    mac_led_data_t* data = g_tree_lookup(ledger->mac_accounts, ledger->roger_addr);
    data->balance += token->value;
    return MT_SUCCESS;
}

/**
 * Handles a transfer of funds between two standard balances.
 */
int handle_mac_any_trans(mt_ledger_t* ledger, mac_any_trans_t* token, byte (*addr)[MT_SZ_ADDR]){

    // check that the message originates from the payer
    if(memcmp(addr, token->from, MT_SZ_ADDR) != 0)
	return MT_ERROR;

    mac_led_data_t* data_from = g_tree_lookup(ledger->mac_accounts, token->from);

    // check that the "from" address exists
    if(data_from == NULL)
	return MT_ERROR;

    mac_led_data_t* data_to = g_tree_lookup(ledger->mac_accounts, token->to);
    // if the address doesn't exist then create it

    if(data_to == NULL){
	byte* new_addr = malloc(MT_SZ_ADDR);
	memcpy(new_addr, token->to, MT_SZ_ADDR);
	data_to = calloc(1, sizeof(mac_led_data_t));
	g_tree_insert(ledger->mac_accounts, new_addr, data_to);
    }

    int* bal_from = &(data_from->balance);
    int* bal_to = &(data_to->balance);
    if(transfer(ledger, bal_from, bal_to, token->val_from, token->val_to, ledger->fee) != MT_SUCCESS)
	return MT_ERROR;
    return 0;
}

/**
 * Initializes a new channel address using escrowed funds from a standard
 * address. The initializing user is considered to be the end user in this
 * channel. At this point, the channel is not very useful since the intermediary
 * has not completed the setup, but the funds are still recoverable.
 */
int handle_chn_end_escrow(mt_ledger_t* ledger, chn_end_escrow_t* token, byte (*addr)[MT_SZ_ADDR]){

    // check that the message originates from the payer
    if(memcmp(addr, token->from, MT_SZ_ADDR) != 0)
	return MT_ERROR;

    mac_led_data_t* data_from = g_tree_lookup(ledger->mac_accounts, token->from);
    chn_led_data_t* data_chn = g_tree_lookup(ledger->chn_accounts, token->chn);

    // check that the from address exists
    if(data_from == NULL)
	return MT_ERROR;

    // if the channel doesn't exist then create one
    if(data_chn == NULL){
	byte* new_addr = malloc(MT_SZ_ADDR);
	memcpy(new_addr, token->chn, MT_SZ_ADDR);
	data_chn = calloc(1, sizeof(chn_led_data_t));
	data_chn->state = MT_LSTATE_EMPTY;
	g_tree_insert(ledger->chn_accounts, new_addr, data_chn);
    }

    // check that we have a new and unused channel address
    if(data_chn->state != MT_LSTATE_EMPTY)
	return MT_ERROR;

    int* bal_from = &(data_from->balance);
    int* bal_to = &(data_chn->end_balance);

    // check that the escrow transfer goes through
    if(transfer(ledger, bal_from, bal_to, token->val_from, token->val_to, ledger->fee) == MT_ERROR){
	return MT_ERROR;
    }

    memcpy(data_chn->end_addr, addr, MT_SZ_ADDR);
    data_chn->end_chn_token = token->chn_token;
    data_chn->state = MT_LSTATE_INIT;
    return 0;
}

/**
 * Respond to an existing initialized channel to serve as the channel
 * intermediary. Once this operation completes, the channel is considered open
 * for micro/nanopayment processing. Funds will not be recoverable until the
 * channel closure protocol is completed by both parties.
 */
int handle_chn_int_escrow(mt_ledger_t* ledger, chn_int_escrow_t* token, byte (*addr)[MT_SZ_ADDR]){

    // check that the message originates from the payer
    if(memcmp(addr, token->from, MT_SZ_ADDR) != 0)
	return MT_ERROR;

    mac_led_data_t* data_from = g_tree_lookup(ledger->mac_accounts, token->from);
    chn_led_data_t* data_chn = g_tree_lookup(ledger->chn_accounts, token->chn);

    // check that both channels exist
    if(data_from == NULL || data_chn == NULL)
	return MT_ERROR;

    // check that the channel address is in the right state
    if(data_chn->state != MT_LSTATE_INIT)
	return MT_ERROR;

    int* bal_from = &(data_from->balance);
    int* bal_to = &(data_chn->int_balance);

    // check that the escrow transfer goes through
    if(transfer(ledger, bal_from, bal_to, token->val_from, token->val_to, ledger->fee) == MT_ERROR)
	return MT_ERROR;

    memcpy(data_chn->int_addr, addr, MT_SZ_ADDR);
    data_chn->int_chn_token = token->chn_token;
    data_chn->state = MT_LSTATE_OPEN;
    return 0;
}

/**
 * Request by the intermediary to close out a channel. At this point, the
 * intermediary does not know what the final balances should be. As a result,
 * the end user must respond with a closure message within the specified time
 * limit or risk losing the entire balance of her funds.
 */
int handle_chn_int_reqclose(mt_ledger_t* ledger, chn_int_reqclose_t* token, byte (*addr)[MT_SZ_ADDR]){

    chn_led_data_t* data_chn = g_tree_lookup(ledger->chn_accounts, token->chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that message is coming from the intermediary
    if(memcmp(data_chn->int_addr, addr, MT_SZ_ADDR) != 0)
	return MT_ERROR;

    // check that the channel is in the right state
    if(!(data_chn->state == MT_LSTATE_OPEN))
	return MT_ERROR;

    data_chn->close_epoch = ledger->epoch + ledger->close_window;
    data_chn->state = MT_LSTATE_INT_REQCLOSED;
    return 0;
}

/**
 * Request by the end user to close out a channel. The end user posts her view
 * of the current channel balance. The intermediary now has some specified time
 * limit to refute the claim before the channel can be cashed out.
 */
int handle_chn_end_close(mt_ledger_t* ledger, chn_end_close_t* token, byte (*addr)[MT_SZ_ADDR]){

    chn_led_data_t* data_chn = g_tree_lookup(ledger->chn_accounts, token->chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that message is coming from the end user
    if(memcmp(data_chn->end_addr, addr, MT_SZ_ADDR) != 0)
	return MT_ERROR;

    // check that the channel is in the right state
    if(!(data_chn->state == MT_LSTATE_OPEN || data_chn->state == MT_LSTATE_INT_REQCLOSED))
	return MT_ERROR;

    data_chn->end_close_token = *token;
    data_chn->close_epoch = ledger->epoch + ledger->close_window;
    data_chn->state = MT_LSTATE_END_CLOSED;
    return 0;
}

/**
 * Operation by the intermediary to either accept the end user's view of the
 * channel balances or refute the claim with another view. The network resolves
 * the dispute and outputs the final channel balances.
 */
int handle_chn_int_close(mt_ledger_t* ledger, chn_int_close_t* token, byte (*addr)[MT_SZ_ADDR]){

    chn_led_data_t* data_chn = g_tree_lookup(ledger->chn_accounts, token->chn);

    // check that the channel address exists and is a channel address
    if(data_chn == NULL)
	return MT_ERROR;

    // check that message is coming from the intermediary
    if(memcmp(data_chn->int_addr, addr, MT_SZ_ADDR) != 0)
	return MT_ERROR;

    // check that the channel address is in the right state
    if(!(data_chn->state == MT_LSTATE_END_CLOSED))
	return MT_ERROR;

    data_chn->int_close_token = *token;
    data_chn->state = MT_LSTATE_INT_CLOSED;
    return 0;
}

/**
 * Operation by the end user to cash out of a payment channel. This can only be
 * done by the end user if the channel has not been initialized by the
 * intermediary or after the channel has/should be closed.
 */
int handle_chn_end_cashout(mt_ledger_t* ledger, chn_end_cashout_t* token, byte (*addr)[MT_SZ_ADDR]){

    chn_led_data_t* data_chn = g_tree_lookup(ledger->chn_accounts, token->chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that the from address is the channel end user
    if(memcmp(addr, data_chn->end_addr, MT_SZ_ADDR))
	return MT_ERROR;

    mac_led_data_t* data_to = g_tree_lookup(ledger->mac_accounts, addr);

    // attempt to close the channel if it isn't already
    if(close_channel(ledger, data_chn) == MT_ERROR)
	return MT_ERROR;

    int* bal_from = &(data_chn->end_balance);
    int* bal_to = &(data_to->balance);

    // check that the transfer goes through
    return transfer(ledger, bal_from, bal_to, token->val_from, token->val_to, ledger->fee);
}

/**
 * Operation by the intermediary to cash out of a payment channel. This can only
 * be done after the channel has/should be closed.
 */
int handle_chn_int_cashout(mt_ledger_t* ledger, chn_int_cashout_t* token, byte (*addr)[MT_SZ_ADDR]){

    chn_led_data_t* data_chn = g_tree_lookup(ledger->chn_accounts, token->chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that the from address is the channel intermediary
    if(memcmp(addr, data_chn->int_addr, MT_SZ_ADDR))
	return MT_ERROR;

    mac_led_data_t* data_to = g_tree_lookup(ledger->mac_accounts, addr);

    // attempt to close the channel if it isn't already
    if(close_channel(ledger, data_chn) == MT_ERROR)
	return MT_ERROR;

    int* bal_from = &(data_chn->int_balance);
    int* bal_to = &(data_to->balance);

    // check that the transfer goes through
    int val_roger = ledger->fee + token->val_to * ledger->tax;
    return transfer(ledger, bal_from, bal_to, token->val_from, token->val_to, val_roger);
}

int handle_mac_led_query(mt_ledger_t* ledger, mac_led_query_t* token, mt_desc_t desc){

    mac_led_data_t* mac_ptr = g_tree_lookup(ledger->mac_accounts, token->addr);

    // check that address exists
    if(mac_ptr == NULL)
	return MT_ERROR;

    cell_t* cells;
    int num_cells = pack_mac_led_data(*mac_ptr, &ledger->led_pk, &ledger->led_sk, &cells);
    if(num_cells < 0)
	return MT_ERROR;

    // send the requested data
    if(ledger->send_cells(desc, cells, num_cells) != MT_SUCCESS)
	return MT_ERROR;

    // signal that we can close the connection
    if(ledger->close_conn(desc) != MT_SUCCESS)
	return MT_ERROR;

    return MT_SUCCESS;
}

int handle_chn_led_query(mt_ledger_t* ledger, chn_led_query_t* token, mt_desc_t desc){

    chn_led_data_t* chn_ptr = g_tree_lookup(ledger->chn_accounts, token->addr);

    // check that address exists
    if(chn_ptr == NULL)
	return MT_ERROR;

    cell_t* cells;
    int num_cells = pack_chn_led_data(*chn_ptr, &ledger->led_pk, &ledger->led_sk, &cells);
    if(num_cells < 0)
	return MT_ERROR;

    // send the requested data
    if(ledger->send_cells(desc, cells, num_cells) != MT_SUCCESS)
	return MT_ERROR;

    // signal that we can close the connection
    if(ledger->close_conn(desc) != MT_SUCCESS)
	return MT_ERROR;

    return MT_SUCCESS;
}



//------------------------------- Helper Functions --------------------------------------//

int addr_compare(gconstpointer a, gconstpointer b){
    return memcmp(a, b, MT_SZ_ADDR);
}

/**
 * Transfer the specified amounts from one balance to another (provided in
 * pointers). Ensure that the value difference covers the ledger's specified
 * cost of transaction.
 */
int transfer(mt_ledger_t* ledger, int* bal_from, int* bal_to, int val_from, int val_to, int val_roger){
    // check that the payment values make sense
    if(!(val_from > val_to && val_to > 0))
	return MT_ERROR;

    // check that the payer has a sufficient balance
    if(*bal_from < val_from)
	return MT_ERROR;
    // check that the payment different covers the ledger profit
    if(val_from - val_to < val_roger)
	return MT_ERROR;

    *bal_from -= val_from;
    *bal_to += val_to;

    mac_led_data_t* roger_data = g_tree_lookup(ledger->mac_accounts, ledger->roger_addr);
    roger_data->balance += (val_from - val_to);
    return 0;
}

/**
 * Process a request to close the given channel. This function considers all
 * possible states of the channel. If channel closure is allowed, then it marks
 * the channel as closed and updates the final balances.
 */
int close_channel(mt_ledger_t* ledger, chn_led_data_t* data){

    // channel is already closed
    if(data->state == MT_LSTATE_RESOLVED)
	return 0;

    // cannot close channel
    if(data->state == MT_LSTATE_EMPTY || data->state == MT_LSTATE_OPEN)
	return MT_ERROR;

    // one part has closed the channel but not enough time has passed
    if((data->state == MT_LSTATE_INT_REQCLOSED || data->state == MT_LSTATE_END_CLOSED) &&
	data->close_epoch + ledger->close_window < ledger->epoch)
	return MT_ERROR;

    int* end_bal = NULL;
    int* int_bal = NULL;
    resolve(&ledger->pp, data->end_chn_token, data->int_chn_token,
	    data->end_close_token, data->int_close_token, end_bal, int_bal);

    if(end_bal != NULL && int_bal != NULL){
	data->end_balance = *end_bal;
	data->int_balance = *int_bal;
    }

    data->state = MT_LSTATE_RESOLVED;
    return 0;
}

//------------------------------- moneTor Algorithms ------------------------------------//

/**
 * Resolve algorithm implemente from the moneTor protocol algorithms. Accepts
 * channel information at closure and makes a determination on the final balances.
 */
void resolve(byte (*pp)[MT_SZ_PP], chn_end_chntok_t T_E, chn_int_chntok_t T_I,
	    chn_end_close_t rc_E, chn_int_close_t rc_I, int* end_bal, int* int_bal){}
