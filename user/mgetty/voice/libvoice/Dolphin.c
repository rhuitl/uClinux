/*
 * Dolphin.c
 *
 * This file contains the Dolphin specific hardware stuff.
 *
 * This file is based on the dutch documentation mailed to me by
 * Pascal <pern@ramoth.xs4all.nl>. Since I don't have a Dolphin
 * modem, I cannot test nor debug this driver. But I'm quite
 * optimistic that it will work.
 *
 * Marc
 *
 * $Id: Dolphin.c,v 1.8 2005/03/13 17:27:45 gert Exp $
 *
 */

#include "../include/voice.h"

static int Dolphin_init (void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing Dolphin voice modem");

     /*
      * AT+VNH=1 - Disable automatic hangup.
      */

     if (voice_command("AT+VNH=1", "OK") != VMA_USER_1)
          lprintf(L_WARN, "disabling automatic hangup didn't work");

     /*
      * AT+VSD=x,y - Set silence threshold and duration.
      */

     sprintf(buffer, "AT+VSD=%d,%d", cvd.rec_silence_threshold.d.i * 31 / 100,
      cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting recording preferences didn't work");

     voice_modem_state = IDLE;
     return(OK);
     }

static int Dolphin_set_compression (int *compression, int *speed, int *bits)
     {
     reset_watchdog();

     if (*compression == 0)
          *compression = 2;

     if (*speed == 0)
          *speed = 9600;

     if (*speed != 9600)
          {
          lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name,
           *speed);
          return(FAIL);
          };

     if (*compression != 2)
          {
          lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
           voice_modem_name, *compression);
          return(FAIL);
          };

     *bits = 2;

     if (voice_command("AT+VSM=2", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

static int Dolphin_set_device (int device)
     {
     reset_watchdog();

     switch (device)
          {
          case NO_DEVICE:

               if (voice_write("AT+VLS=0") != OK)
                    return(FAIL);

               if (voice_command("", "AT+VLS=0|OK") == VMA_USER_1)
                    voice_command("", "OK");

               return(OK);
          case DIALUP_LINE:
               voice_command("AT+VLS=2", "VCON");
               return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT+VLS=16", "VCON");
               return(OK);
          };

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

const char Dolphin_pick_phone_cmnd[] = "ATA";
const char Dolphin_pick_phone_answr[] = "VCON";

voice_modem_struct Dolphin =
     {
     "Dolphin",
     "Dolphin",
     (char *) Dolphin_pick_phone_cmnd,
     (char *) Dolphin_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
     (char *) IS_101_beep_answr,
              IS_101_beep_timeunit,
     (char *) IS_101_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) IS_101_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) IS_101_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) IS_101_intr_play_cmnd,
     (char *) IS_101_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) IS_101_stop_play_answr,
     (char *) IS_101_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) IS_101_stop_rec_cmnd,
     (char *) IS_101_stop_rec_answr,
     (char *) IS_101_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) IS_101_ask_mode_cmnd,
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
     &Dolphin_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Dolphin_set_compression,
     &Dolphin_set_device,
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
