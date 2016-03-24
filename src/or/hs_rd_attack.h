
/**
 * \file hs_rd_attack.h
 * \brief Header file for hs_rd_attacK.c
 **/

#ifndef TOR_HS_RD_ATTACK_H
#define TOR_HS_RD_ATTACK_H

#define INITIALIZED 1
#define ATTACK_STATE_CONNECT_TO_INTRO 2

typedef enum {
  INITIALIZED=0,
  ATTACK_STATE_CONNECT_TO_INTRO=1
} attack_state_t;

typedef enum {
  ESTABLISH_RDV=0,
  SEND_RD=1
} hs_attack_cmd_t;

typedef struct hs_rd_attack_t{
  /* contain information needed to carry out the attack*/
  connection_t *conn;
  attack_state_t state;
  origin_circuit_t *circ_to_intro;
  origin_circuit_t *rendcircs;
  rend_data_t *onionservice;
}hs_rd_attack_t;

typedef struct hs_attack_stats_t {
} hs_attack_stats_t;

int init_conn_circuit(uint8_t);

int send_RD_cells(hs_rd_attack_t *);

void free_hs_rd_attack();

#endif
