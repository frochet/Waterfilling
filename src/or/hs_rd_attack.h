
/**
 * \file hs_rd_attack.h
 * \brief Header file for hs_rd_attacK.c
 **/

#ifndef TOR_HS_RD_ATTACK_H
#define TOR_HS_RD_ATTACK_H


typedef struct hs_rd_attack_t{
  /* contain information needed to carry out the attack*/
  connection_t *conn;
  uint8_t state;
  origin_circuit_t *circ;

}hs_rd_attack_t;

int init_conn_circuit(hs_rd_attack_t *attack_infos);

int send_RD_cells(hs_rd_attack_t *attack_infos);

#endif
