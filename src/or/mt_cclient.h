#ifndef mt_cclient_h
#define mt_cclient_h

#include "mt_common.h"
/**
 * Controller moneTor client part
 */


void mt_cclient_intermediary_circ_has_closed(origin_circuit_t *circ);

void mt_cclient_intermediary_circ_has_opened(origin_circuit_t *circ);

#define MAX_INTERMEDIARY_LINKED_TO_MIDDLE 1
#define MAX_INTERMEDIARY_LINKED_TO_EXIT 1
//XXX MoneTor - define following as the sum of the two above
#define MAX_INTERMEDIARY_CHOSEN 2 // XXX MoneTor - do we need backup intermediaries?




/** Gets called every second, job:
 */
void run_cclient_scheduled_events(time_t now);


//handle intermediaries
//XXX MoneTor maybe all of intermediary-handling
//    function need to be in a separate file?

smartlist_t* get_node_t_smartlist_intermerdiaries(void);

smartlist_t* get_intermediaries(int for_circuit);

/* Get one intermediary usable for position */
intermediary_t* get_intermediary_by_role(position_t position);

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
extend_info_t* mt_cclient_get_intermediary_from_edge(edge_connection_t* conn);


/**
 * Get the intermediary whose identity is linked to that origin_circuit_t 
 */
intermediary_t* mt_cclient_get_intermediary_from_ocirc(origin_circuit_t* circ);

/********************** Payment actions *************************************/

/**
 * Interface from the circuit code to initiate the payment module when a first
 * stream is attached to a general circuit
 */

void mt_cclient_launch_payment(origin_circuit_t* circ);

/****************************************************************************/

void mt_cclient_init(void);

/**
 * Parse the state file to get the intermediaries we were using before
 *
 * NOT URGENT
 */
int intermediary_parse_state(or_state_t *state, int set, char** msg);

#endif
