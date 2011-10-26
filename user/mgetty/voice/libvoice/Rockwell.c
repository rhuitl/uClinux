/*
 * Rockwell.c
 *
 * This file contains the DYNALINK V1414VQE specific hardware stuff.
 *
 * This file is originally written for the Elsa 28.8 modem by:
 * Stefan Froehlich <Stefan.Froehlich@tuwien.ac.at>.
 *
 * Since commands are the same I've copied the code, and left out some
 * Elsa features....
 * The rockwell/dynalink V1414VQE is now maintained by:
 * Ard van Breemen <ard@cstmel.hobby.nl>.
 *
 * Removed most stuff from this file, since the new IS-101 driver can be
 * used now. (Marc 04.01.1997)
 *
 * $Id: Rockwell.c,v 1.10 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static int Rockwell_handle_dle(char data)
     {

     switch (data)
          {

          /*
           * Local handset goes off hook
           */

          case 't':
               return(queue_event(create_event(HANDSET_OFF_HOOK)));

          }

     return(IS_101_handle_dle(data));
     }

static int Rockwell_init(void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     lprintf(L_MESG, "initializing ROCKWELL voice modem");
     voice_modem_state = INITIALIZING;
     sprintf(buffer, "AT#VSP=%1u", cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence period");

     /* Colin.Panisset@Sun.COM
      *    -- for Spirit Cobra modem (ATI6 == "RCV288DPi Rev 05BA")
      * Will create warnings for non-supporting modems. Zero disables.
      */

     if (cvd.transmit_gain.d.i) {
	if (cvd.transmit_gain.d.i == -1) {
	   cvd.transmit_gain.d.i = 50;
	}
        sprintf(buffer, "AT#TL=%X", (65536 / (100 / cvd.transmit_gain.d.i)));

	if (voice_command(buffer, "OK") != VMA_USER_1) {
          lprintf(L_WARN, "can't set transmit gain");
        }
     }

     if (cvd.receive_gain.d.i) {
	if (cvd.receive_gain.d.i == -1) {
	   cvd.receive_gain.d.i = 50;
	}
        sprintf(buffer, "AT#RG=%X", (65536 / (100 / cvd.receive_gain.d.i)));

	if (voice_command(buffer, "OK") != VMA_USER_1) {
	     lprintf(L_WARN, "can't set record gain");
        }
     }
 
     if (voice_command("AT#VSD=0", "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't disable silence deletion");

     if (voice_command("AT#VTD=3F,3F,3F", "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set DLE responses");

     if ((cvd.rec_silence_threshold.d.i > 100) ||
      (cvd.rec_silence_threshold.d.i < 0))
          {
          lprintf(L_WARN, "Invalid threshold value.");
          return(ERROR);
          }

     sprintf(buffer, "AT#VSS=%1u", cvd.rec_silence_threshold.d.i * 3 / 100);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence threshold");

     if (voice_command("AT&K3", "OK") == VMA_USER_1)
          {
          TIO tio;
          tio_get(voice_fd, &tio);
          tio_set_flow_control(voice_fd, &tio, FLOW_HARD);
          tio_set(voice_fd, &tio);
          }
     else
          lprintf(L_WARN, "can't turn on hardware flow control");

     voice_modem_state = IDLE;
     return(OK);
     }

static int Rockwell_set_compression (int *compression, int *speed, int *bits)
     {
     reset_watchdog();

     if (*compression == 0)
          *compression = 2;

     if (*speed == 0)
          *speed = 7200;

     if (*speed != 7200)
          {
          lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name,
           *speed);
          return(FAIL);
          };

     switch (*compression)
          {
          case 2:
               *bits=2;

               if (voice_command("AT#VBS=2", "OK") != VMA_USER_1)
                    return(FAIL);

               return (OK);
          case 4:
               *bits=4;

               if (voice_command("AT#VBS=4", "OK") != VMA_USER_1)
                    return(FAIL);

               return (OK);
          case 8:
               *bits=8;

               if (voice_command("AT#VBS=8", "OK") != VMA_USER_1)
                    return(FAIL);

               return (OK);
          case 16:
               *bits=16;

               if (voice_command("AT#VBS=16", "OK") != VMA_USER_1)
                    return(FAIL);

               return (OK);
          }

     lprintf(L_WARN,
      "ROCKWELL handle event: Illegal voice compression method (%d)",
      *compression);
     return(FAIL);
     }

static int Rockwell_set_device (int device)
     {
     static int current_device = -1;
     reset_watchdog();

     if ((current_device != device) && (current_device >= 0)) {
          voice_command("ATH0","VCON|OK");
	  /* Sending a ATH0 results in leaving voice mode, at least with the
	   * RC32ACL chipset. -- zukerman@math-hat.com
           * OPEN ISSUE: why do we send ATH0 in the first place ?
	   */
	  voice_command("AT#CLS=8", "OK");
     }

     current_device=device;

     switch (device)
          {
          case NO_DEVICE:
               voice_command("AT#VLS=0", "OK");
               return(OK);
          case DIALUP_LINE:
               voice_command("AT#VLS=4", "OK");
               return(OK);
          case EXTERNAL_MICROPHONE:
               voice_command("AT#VLS=3", "VCON");
               return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT#VLS=2", "VCON");
               return(OK);
          case LOCAL_HANDSET:
               voice_command("AT#VLS=1","VCON");
               return(OK);
          }

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

static char Rockwell_pick_phone_cmnd[] = "ATA";
static char Rockwell_pick_phone_answr[] = "VCON";
static char Rockwell_beep_cmnd[] = "AT#VTS=[%d,0,%d]";
#define     Rockwell_beep_timeunit 100
static char Rockwell_hardflow_cmnd[] = "AT&K3";
static char Rockwell_softflow_cmnd[] = "AT&K4";
static char Rockwell_start_play_cmnd[] = "AT#VTX";
static char Rockwell_intr_play_answr[] = "OK|VCON";
static char Rockwell_stop_play_answr[] = "OK|VCON";
static char Rockwell_start_rec_cmnd[] = "AT#VRX";
static char Rockwell_stop_rec_cmnd[] = {'!', 0x00};
static char Rockwell_stop_rec_answr[] = "OK|VCON";
static char Rockwell_switch_mode_cmnd[] = "AT#CLS=";
static char Rockwell_ask_mode_cmnd[] = "AT#CLS?";
static char Rockwell_play_dtmf_cmd[] = "AT#VTS=%c";

voice_modem_struct Rockwell =
     {
     "Rockwell",
     "Rockwell",
     (char *) Rockwell_pick_phone_cmnd,
     (char *) Rockwell_pick_phone_answr,
     (char *) Rockwell_beep_cmnd,
     (char *) IS_101_beep_answr,
              Rockwell_beep_timeunit,
     (char *) Rockwell_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) Rockwell_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) Rockwell_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) IS_101_intr_play_cmnd,
     (char *) Rockwell_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) Rockwell_stop_play_answr,
     (char *) Rockwell_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) Rockwell_stop_rec_cmnd,
     (char *) Rockwell_stop_rec_answr,
     (char *) Rockwell_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) Rockwell_ask_mode_cmnd,
     (char *) IS_101_ask_mode_answr,
     (char *) IS_101_voice_mode_id,
     (char *) Rockwell_play_dtmf_cmd,
     (char *) IS_101_play_dtmf_extra,
     (char *) IS_101_play_dtmf_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     NULL,  /* (char *) V253modem_start_duplex_voice_cmnd, */
     NULL,  /* (char *) V253modemstart_duplex_voice_answr, */
     NULL,  /* (char *) V253modem_stop_duplex_voice_cmnd , */
     NULL,  /* (char *) V253modem_stop_duplex_voice_answr, */
     // juergen.kosel@gmx.de : voice-duplex-patch end

     &IS_101_answer_phone,
     &IS_101_beep,
     &IS_101_dial,
     &Rockwell_handle_dle,
     &Rockwell_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     NULL,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Rockwell_set_compression,
     &Rockwell_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &IS_101_switch_to_data_fax,
     &IS_101_voice_mode_off,
     &IS_101_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &IS_101_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };







