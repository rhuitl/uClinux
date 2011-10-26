/*
 * Supra.c
 *
 * This file contains the Elsa driver hacked up so it works on my
 * SupraExpress 56K.  (PNP ID: SUP2420)
 * it was lightly hack by Rob Ryan (rr2b@pacbell.net) from the Elsa
 * version written by Karlo Gross kg@orion.ddorf.rhein-ruhr.de
 * by using the old version from Stefan Froehlich and the
 * help from Marc Eberhard.
 * You have set port_timeout in voice.conf to a minimum of 15
 * if you use 38400 Baud
 *
 * $Id: Supra.c,v 1.5 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static int Supra_set_device (int device);

static int Supra_init (void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing Supra voice modem");

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

     sprintf(buffer, "ATS30=60");       /* fuer 38400 */

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set S30");

     if (cvd.transmit_gain.d.i == -1)
          cvd.transmit_gain.d.i = 50;

     sprintf(buffer, "AT#VGT=%d", cvd.transmit_gain.d.i * 3 / 100 +
      128);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set speaker volume");

     if (cvd.receive_gain.d.i == -1)
          cvd.receive_gain.d.i = 50;

#ifdef NOT_IMPLENTED
     sprintf(buffer, "AT#VGR=%d", 0);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set record volume");
#endif
     
     voice_modem->set_device(DIALUP_LINE);

     if ((cvd.do_hard_flow.d.i) && (voice_command("AT&K3", "OK") ==
      VMA_USER_1) )
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

static int Supra_set_compression (int *compression, int *speed, int *bits)
     {
     reset_watchdog();

     if (*compression == 0)
          *compression = 2;

     if (*speed == 0)
          *speed = 7200;

     /* supra express has 7200 and 11025 */
     if (*speed != 7200 && *speed != 11025)
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

static int Supra_set_device (int device)
     {
     reset_watchdog();

     switch (device)
          {
          case NO_DEVICE:
               lprintf(L_JUNK, "%s: _NO_DEV: (%d)", voice_modem_name, device);
               voice_command("AT#VLS=0", "OK");
               return(OK);
          case DIALUP_LINE:
               lprintf(L_JUNK, "%s: _DIALUP: (%d)", voice_modem_name, device);
               voice_command("AT#VLS=4", "OK");
	       return(OK);
          case INTERNAL_MICROPHONE:
	       lprintf(L_JUNK, "%s: _INT_MIC: (%d)", voice_modem_name, device);
	       /* not quite right... on the supra express this is supposed to be the telephone handset.  (rr2b@pacbell.net)*/
               voice_command("AT#VLS=8", "VCON");
	       return(OK);
          case INTERNAL_SPEAKER:
               lprintf(L_JUNK, "%s: _INT_SEAK: (%d)", voice_modem_name, device);
               voice_command("AT#VLS=2", "VCON");
               return(OK);
          }

     lprintf(L_WARN, "%s: Unknown device (%d)", voice_modem_name, device);
     return(FAIL);
     }

static char Supra_pick_phone_cmnd[] = "ATA";
static char Supra_pick_phone_answr[] = "VCON|+VCON";
static char Supra_beep_cmnd[] = "AT#VTS=[%d,0,%d]";
#define     Supra_beep_timeunit 100
static char Supra_hardflow_cmnd[] = "AT&K3";
static char Supra_softflow_cmnd[] = "AT";
static char Supra_start_play_cmnd[] = "AT#VTX";
static char Supra_intr_play_cmnd[] = {DLE, CAN, 0x00};
static char Supra_intr_play_answr[] = "OK|VCON";
static char Supra_stop_play_answr[] = "OK|VCON";
static char Supra_start_rec_cmnd[] = "AT#VRX";
static char Supra_stop_rec_cmnd[] = "!";
static char Supra_stop_rec_answr[] = "OK|VCON";
static char Supra_switch_mode_cmnd[] = "AT#CLS=";
static char Supra_ask_mode_cmnd[] = "AT#CLS?";

voice_modem_struct Supra =
    {
    "SupraExpress 56K",
    "Rockwell",
     (char *) Supra_pick_phone_cmnd,
     (char *) Supra_pick_phone_answr,
     (char *) Supra_beep_cmnd,
     (char *) IS_101_beep_answr,
              Supra_beep_timeunit,
     (char *) Supra_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) Supra_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) Supra_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) Supra_intr_play_cmnd,
     (char *) Supra_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) Supra_stop_play_answr,
     (char *) Supra_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) Supra_stop_rec_cmnd,
     (char *) Supra_stop_rec_answr,
     (char *) Supra_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) Supra_ask_mode_cmnd,
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
    &Supra_init,
    &IS_101_message_light_off,
    &IS_101_message_light_on,
    &IS_101_start_play_file,
    NULL,
    &IS_101_stop_play_file,
    &IS_101_play_file,
    &IS_101_record_file,
    &Supra_set_compression,
    &Supra_set_device,
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
