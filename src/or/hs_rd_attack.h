
/**
 * \file hs_rd_attack.h
 * \brief Header file for hs_rd_attacK.c
 **/

#ifndef TOR_HS_RD_ATTACK_H
#define TOR_HS_RD_ATTACK_H

#define RETRY_THRESHOLD 5

#include "or.h"
#include "circuituse.h"
#include "rendclient.h"
#include "util.h"
#include "control.h"

typedef enum {
  INITIALIZED=0,
  ATTACK_STATE_CONNECT_TO_INTRO=1
} attack_state_t;

typedef enum {
  REND_CIRC_BUILDING = 1,
  REND_CIRC_READY_FOR_INTRO=2,
  REND_CIRC_READY_FOR_RD=3,
  REND_CIRC_INTRO_CELL_SENT=6,
  INTRO_CIRC_BUILDING=4,
  INTRO_CIRC_READY=5
} circuit_state_t;

typedef enum {
  ESTABLISH_RDV=0,
  SEND_RD=1
} hs_attack_cmd_t;

typedef struct circ_info_t {
  origin_circuit_t* circ;
  circuit_state_t state;
} circ_info_t;

typedef struct hs_attack_stats_t {
  int tot_cells;
  int nbr_rendcircs;
} hs_attack_stats_t;

typedef struct hs_rd_attack_t {
  /* contain information needed to carry out the attack*/
  connection_t *conns;
  attack_state_t state;
  circ_info_t *circ_to_intro;
  smartlist_t *rendcircs;
  rend_data_t *onionservice;
  hs_attack_stats_t *stats;
  int retry_intro;
} hs_rd_attack_t;



hs_attack_stats_t*  hs_attack_entry_point(hs_attack_cmd_t, const char*, int, time_t*);

int hs_attack_init_rendezvous_circuits(int, const char*);

int hs_attack_init_intro_circuit(int);

int hs_attack_send_RD_cells(hs_rd_attack_t *);

void hs_attack_mark_rendezvous_ready(origin_circuit_t*);

void hs_attack_mark_intro_ready();

void hs_attack_send_intro_cell_callback(origin_circuit_t*);

void hs_attack_intro_circ_callback();

void hs_attack_launch(time_t*);

void hs_attack_free();

#endif
