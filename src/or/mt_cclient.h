#ifndef mt_cclient_h
#define mt_cclient_h

/**
 * Controller moneTor client part
 */

/** Gets called every second, job:
 *
 * XXX MoneTor Todo
 */
void run_cclient_scheduled_events(time_t now);

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
extend_info_t* mt_cclient_get_intermediary_from_edge(edge_connection_t* conn);

/**
 * Parse the state file to get the intermediaries we were using before
 *
 * NOT URGENT
 */
int intermediary_parse_state(or_state_t *state, int set, char** msg);
#endif
