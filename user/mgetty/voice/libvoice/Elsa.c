/*
 * Elsa.c
 *
 * This file contains the Elsa 28.8 TQV and TKR Tristar 28.8
 * specific hardware stuff.
 * it was written by Karlo Gross kg@orion.ddorf.rhein-ruhr.de
 * by using the old version from Stefan Froehlich and the
 * help from Marc Eberhard.
 * You have set port_timeout in voice.conf to a minimum of 15
 * if you use 38400 Baud
 *
 * $Id: Elsa.c,v 1.14 2005/03/13 17:27:45 gert Exp $
 *
 */

#include "../include/voice.h"
#include "../include/V253modem.h"

static char Elsa_hardflow_cmnd[] = "AT+IFC=2,2";
static char Elsa_hardflow_cmnd_alternate[] = "AT\\Q3";

static int Elsa_set_device (int device);

static int Elsa_init (void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing Elsa voice modem");

     sprintf(buffer, "AT#VSP=%1u", cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence_len VSP");

     sprintf(buffer, "AT#VSD=0");

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set VSD=0");

     sprintf(buffer, "AT#VBS=4");                 /* for 38400 */

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set VBS=4");

     sprintf(buffer, "AT#BDR=16");                /* for 38400 */

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set BDR=16");

     sprintf(buffer, "AT#VTD=3F,3F,3F");

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set VTD=3F");

     sprintf(buffer, "AT#VSS=%1u", cvd.rec_silence_threshold.d.i * 3 / 100);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence threshold VSS");

     sprintf(buffer, "ATS30=60");       /* setting the data-inactivity-timer in the voice part ??? */

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set S30");

     if (cvd.transmit_gain.d.i == -1)
          cvd.transmit_gain.d.i = 50;

     sprintf(buffer, "AT#VGT=%d", cvd.transmit_gain.d.i * 127 / 100 +
      128);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set speaker volume");

     if (cvd.receive_gain.d.i == -1)
          cvd.receive_gain.d.i = 50;

     sprintf(buffer, "AT#VGR=%d", cvd.receive_gain.d.i * 127 / 100 +
      128);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set record volume");

     /* Delay after ringback or before any ringback
      * before modem assumes phone has been answered.
      */
     sprintf(buffer,
             "AT+VRA=%d;+VRN=%d",
             cvd.ringback_goes_away.d.i,         /* 1/10 seconds */
             cvd.ringback_never_came.d.i/10);    /* seconds */

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting ringback delay didn't work");     

     voice_modem->set_device(DIALUP_LINE);

     /* Try new Elsa command first, then old one if it fails.
      * Update the structure.
      */
     if (cvd.do_hard_flow.d.i) {
       int succeeded = 0;

       if (voice_command(Elsa_hardflow_cmnd, "OK") == VMA_USER_1) {
          succeeded = 1;
       }
       else {
	 if (voice_command(Elsa_hardflow_cmnd_alternate, "OK") == VMA_USER_1) {
 	    /* Assuming it's ok to change it now */
            Elsa.hardflow_cmnd = Elsa_hardflow_cmnd_alternate;
            succeeded = 1;
         }
       }

       if (succeeded) {
	 TIO tio;
	 tio_get(voice_fd, &tio);
	 tio_set_flow_control(voice_fd, &tio, FLOW_HARD);
	 tio_set(voice_fd, &tio);
       }
       else {
	 lprintf(L_WARN, "can't turn on hardware flow control");
       }
     }

     voice_modem_state = IDLE;
     return(OK);
     }

static int Elsa_set_compression (int *compression, int *speed, int *bits)
     {
     reset_watchdog();

     if (*compression == 0)
          *compression = 2;

     if (*speed == 0)
          *speed = 7200;

     if (*speed != 7200)
          {
          lprintf(L_WARN, "%s: Illegal sample speed (%d)",
           voice_modem_name, *speed);
          return(FAIL);
          };

     if (*compression == 2)
          {
          voice_command("AT#VBS=2", "OK");
          *bits = 2;
          return(OK);
          }
     if (*compression == 3)
          {
          voice_command("AT#VBS=3", "OK");
          *bits = 3;
          return(OK);
          }
     if (*compression == 4)
          {
          voice_command("AT#VBS=4", "OK");
          *bits = 4;
          return(OK);
          }

     lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
      voice_modem_name, *compression);
     return(FAIL);
     }

static int Elsa_set_device (int device)
     {
       int Result;
       reset_watchdog();

       lprintf(L_JUNK, "%s: %s: (%d)", voice_modem_name, 
	       voice_device_mode_name(device), device);

       switch (device)
	 {
	   /* The newer modems answer with OK
	    * but there are other variants wich answer 
	    * VCON
	    */
	 case NO_DEVICE:
	   Result = voice_command("AT#VLS=0", "OK|VCON");
	   break;
	 case DIALUP_LINE:
	   Result = voice_command("AT#VLS=0", "OK|VCON");
	   break;
	 case DIALUP_WITH_INT_SPEAKER:
	   Result = voice_command("AT#VLS=4", "OK|VCON");
	   break;
	 case INTERNAL_MICROPHONE:
	   Result = voice_command("AT#VLS=3", "OK|VCON");
	   break;
	 case INTERNAL_SPEAKER:
	   Result = voice_command("AT#VLS=2", "OK|VCON");
	   break;
	 case DIALUP_WITH_INTERNAL_MIC_AND_SPEAKER:
	   Result = voice_command("AT#VLS=5", "OK|VCON");
	   break;
	 case LOCAL_HANDSET:
	   Result = voice_command("AT#VLS=1", "OK|VCON");
	   break;
	 default:
	   lprintf(L_WARN, "%s: Unknown device (%d)", 
		   voice_modem_name, device);
	   return(FAIL);
          }

       if ((Result != VMA_USER_1) && (Result != VMA_USER_2))
	 {
	   lprintf(L_WARN,
		   "can't set %s (modem hardware can't do that), error 0x%x",
		   voice_device_mode_name(device),
		   Result);
	   return(VMA_DEVICE_NOT_AVAIL);       
	 }
       return(OK);
     }

static char Elsa_pick_phone_cmnd[] = "ATA";
static char Elsa_pick_phone_answr[] = "VCON|+VCON";
static char Elsa_beep_cmnd[] = "AT#VTS=[%d,0,%d]";
#define     Elsa_beep_timeunit 100
static char Elsa_start_play_cmnd[] = "AT#VTX";
static char Elsa_intr_play_cmnd[] = {DLE, CAN, 0x00};
static char Elsa_intr_play_answr[] = "OK|VCON";
static char Elsa_stop_play_answr[] = "OK|VCON";
static char Elsa_start_rec_cmnd[] = "AT#VRX";
static char Elsa_stop_rec_cmnd[] = "!";
static char Elsa_stop_rec_answr[] = "OK|VCON";
static char Elsa_switch_mode_cmnd[] = "AT#CLS=";
static char Elsa_ask_mode_cmnd[] = "AT#CLS?";

voice_modem_struct Elsa =
    {
    "Elsa MicroLink",
    ELSA_RMD_NAME,
     (char *) Elsa_pick_phone_cmnd,
     (char *) Elsa_pick_phone_answr,
     (char *) Elsa_beep_cmnd,
     (char *) IS_101_beep_answr,
              Elsa_beep_timeunit,
     (char *) Elsa_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) V253modem_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) Elsa_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) Elsa_intr_play_cmnd,
     (char *) Elsa_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) Elsa_stop_play_answr,
     (char *) Elsa_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) Elsa_stop_rec_cmnd,
     (char *) Elsa_stop_rec_answr,
     (char *) Elsa_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) Elsa_ask_mode_cmnd,
     (char *) IS_101_ask_mode_answr,
     (char *) IS_101_voice_mode_id,
     (char *) IS_101_play_dtmf_cmd,
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
    &IS_101_handle_dle,
    &Elsa_init,
    &IS_101_message_light_off,
    &IS_101_message_light_on,
    &IS_101_start_play_file,
    NULL,
    &IS_101_stop_play_file,
    &IS_101_play_file,
    &IS_101_record_file,
    &Elsa_set_compression,
    &Elsa_set_device,
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
