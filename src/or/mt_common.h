#ifndef mt_common_h
#define mt_common_h

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"

int mt_pk2addr(byte (*pk)[MT_SZ_PK], byte (*addr_out)[MT_SZ_ADDR]);
int mt_addr2hex(byte (*addr)[MT_SZ_ADDR], char (*hex_out)[MT_SZ_ADDR * 2 + 3]);

int mt_hc_create(int size, byte (*head)[MT_SZ_HASH], byte (*hc_out)[][MT_SZ_HASH]);
int mt_hc_verify(byte (*tail)[MT_SZ_HASH], byte (*preimage)[MT_SZ_HASH], int k);

/** Canibalize a general circuit => extends it to
 *  the intermediary point described by ei
 *
 *  ret 0 on success
 */
int mt_circuit_launch_intermediary(extend_info_t* ei);

/** Callback function called when an intermediary
 *  circuit is open
 */
void mt_circuit_intermediary_has_opened(origin_circuit_t* circuit);

void mt_init(void);

/**
 * Has enough funds to pay for prioritization? returns 1 or 0
 */
int mt_check_enough_fund(void);

/**
 * gets called by the main loop every second.
 */
void monetor_run_scheduled_events(time_t now);
#endif
