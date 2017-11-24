#ifndef mt_cclient_h
#define mt_cclient_h

#include "mt_common.h"
/**
 * Controller moneTor client part
 */


void mt_cclient_intermediary_circ_has_closed(origin_circuit_t *circ);

static intermediary_t* intermediary_new(const node_t *node, extend_info_t *ei, time_t now);

#define MAX_INTERMEDIARY_CHOSEN 2 // XXX MoneTor - do we need backup intermediaries?
/*
 * Fill the intermediaries smartlist_t with selected
 * intermediary_t
 *
 * XXX MoneTor - parse the state file to recover previously
 *               intermediaries
 * 
 * If no intermediaries in the statefile, select new ones
 */
static void choose_intermediaries(time_t now, smartlist_t *exclude_list);

/**
 * 
 * Remove the intermdiary from the list we are using because
 * of one of the following reasons::
 * XXX MoneTor - FR: do we implement all of them?
 * - Node does not exist anymore in the consensus (do we care for simulation?)
 * - The intermediary maximum circuit retry count has been reached (we DO care about that)
 * - The intermediary has expired (we need to cashout and rotate => do we care?)
 */

static void cleanup_intermediary(intermediary_t *intermediary,
    time_t now);

/* Scheduled event run from the main loop every second.
 * Make sure our controller is healthy, including
 * intermediaries status, payment status, etc
 */
STATIC void run_cclient_housekeeping_event(time_t now);

/*
 * Scheduled event run from the main loop every second.
 * Makes sure we always have circuits build towards
 * the intermediaries
 */
STATIC void run_cclient_build_circuit_event(time_t now);

/** Gets called every second, job:
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
 * Get the intermediary whose identity is linked to that origin_circuit_t 
 */
intermediary_t* mt_cclient_get_intermediary_from_ocirc(origin_circuit_t* circ);

void  mt_cclient_init(void);

/**
 * Parse the state file to get the intermediaries we were using before
 *
 * NOT URGENT
 */
int intermediary_parse_state(or_state_t *state, int set, char** msg);

static void intermediary_free(intermediary_t *intermediary);

#endif
