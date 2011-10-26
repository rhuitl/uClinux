/*
 * ZyXEL_1496.c
 *
 * This file contains the ZyXEL 1496 specific hardware stuff.
 *
 * $Id: ZyXEL_1496.c,v 1.9 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static int ZyXEL_1496_init (void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     voice_command("ATI1", "");
     voice_read(buffer);
     voice_read(buffer);
     voice_command("", "OK");
     rom_release = 100 * (buffer[10] - '0') + 10 *
      (buffer[12] - '0') + (buffer[13] - '0');
     lprintf(L_MESG, "ROM release %4.2f detected", rom_release / 100.0);
     lprintf(L_MESG, "initializing ZyXEL 1496 voice modem");

     /*
      * ATS40.3=1 - Enable distincitve ring type 1 (RING)
      * ATS40.4=1 - Enable distincitve ring type 2 (RING 1)
      * ATS40.5=1 - Enable distincitve ring type 3 (RING 2)
      * ATS40.6=1 - Enable distincitve ring type 4 (RING 3)
      */

     if (voice_command("ATS40.3=1 S40.4=1 S40.5=1 S40.6=1", "OK") !=
      VMA_USER_1)
          lprintf(L_WARN, "couldn't initialize distinctive RING");

     /*
      * ATS39.6=1 - Enable DTMF detection after AT+VLS=2
      * ATS39.7=0 - Don't include resynchronization information
      *             in recorded voice data
      * AT+VIT=60 - Set inactivity timer to 60 seconds
      */

     if (voice_command("ATS39.6=1 S39.7=0 +VIT=60", "OK") != VMA_USER_1)
          lprintf(L_WARN, "voice init failed, continuing");

     /*
      * AT+VDH=x - Set the threshold for DTMF detection (0-32)
      * AT+VDD=x - Set DTMF tone duration detection
      */

     sprintf(buffer, "AT+VDH=%d +VDD=%d", cvd.dtmf_threshold.d.i *
      31 / 100, cvd.dtmf_len.d.i / 5);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting DTMF preferences didn't work");

     /*
      * AT+VSD=x,y - Set silence threshold and duration.
      */

     sprintf(buffer, "AT+VSD=%d,%d", cvd.rec_silence_threshold.d.i *
      31 / 100, cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting recording preferences didn't work");

     /*
      * AT+VGT - Set the transmit gain for voice samples.
      */

     if (cvd.transmit_gain.d.i == -1)
          cvd.transmit_gain.d.i = 75;

     sprintf(buffer, "AT+VGT=%d", cvd.transmit_gain.d.i * 255 / 100);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting transmit gain didn't work");

     /*
      * AT+VGR - Set receive gain for voice samples.
      */

     if (cvd.receive_gain.d.i == -1)
          cvd.receive_gain.d.i = 75;

     sprintf(buffer, "AT+VGR=%d", cvd.receive_gain.d.i * 255 / 100);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting receive gain didn't work");

     /*
      * AT+VNH=1 - Disable autohangup
      */

     if (voice_command("AT+VNH=1", "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't disable autohangup");

     /* -- alborchers@steinerpoint.com
      * AT+VRA and AT+VRN - Delay after ringback or before any ringback
      *                     before modem assumes phone has been answered.
      */

     sprintf(buffer, "AT+VRA=%d+VRN=%d",
      cvd.ringback_goes_away.d.i, cvd.ringback_never_came.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN,"setting ringback delay didn't work");

     voice_modem_state = IDLE;
     return(OK);
     }

static int ZyXEL_1496_set_compression (int *compression, int *speed, int *bits)
     {

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

     switch (*compression)
          {
          case 1:
               *bits = 1;

               if (voice_command("AT+VSM=1", "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 2:
               *bits = 2;

               if (voice_command("AT+VSM=2", "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 3:
               *bits = 3;

               if (voice_command("AT+VSM=3", "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 30:
               *bits = 3;

               if (voice_command("AT+VSM=30", "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 4:
               *bits = 4;

               if (voice_command("AT+VSM=4", "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          default:
               lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
                voice_modem_name, *compression);
               return(FAIL);
          };


     return(OK);
     }

static int ZyXEL_1496_set_device (int device)
     {

     switch (device)
          {
          case NO_DEVICE:

               if (voice_write("AT+VLS=0") != OK)
                    return(FAIL);

               if (voice_command("", "AT+VLS=0|OK") == VMA_USER_1)
                    voice_command("", "OK");

               voice_command("AT+VNH=0", "OK");
               return(OK);
          case DIALUP_LINE:
               voice_command("AT+VLS=2", "VCON");
               return(OK);
          case EXTERNAL_MICROPHONE:
               voice_command("AT+VLS=8", "VCON");
               return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT+VLS=16", "VCON");
               return(OK);
          };

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

/* Only verifies the RMD name */
#define ZYXEL_1496_RMD_NAME "ZyXEL 1496"
#define ZYXEL_2864_RMD_NAME "ZyXEL 2864"
int ZyXEL_1496_check_rmd_adequation(char *rmd_name) {
   /* We use hardware values so that this function can be
    * inherited from 2864 too.
    */
   return !strncmp(rmd_name,
                   ZYXEL_1496_RMD_NAME,
                   sizeof(ZYXEL_1496_RMD_NAME))
          || !strncmp(rmd_name,
                      ZYXEL_2864_RMD_NAME,
                      sizeof(ZYXEL_2864_RMD_NAME));
}

static char ZyXEL_1496_pick_phone_answr[] = "VCON";
#define     ZyXEL_1496_beep_timeunit 100
static char ZyXEL_1496_intr_play_cmnd[] = {DLE, DC4, 0x00};
static char ZyXEL_1496_intr_play_answr[] = "VCON";
static char ZyXEL_1496_stop_play_answr[] = "VCON";
static char ZyXEL_1496_stop_rec_answr[] = "VCON";

voice_modem_struct ZyXEL_1496 =
     {
     "ZyXEL 1496",
     ZYXEL_1496_RMD_NAME,
     (char *) IS_101_pick_phone_cmnd,
     (char *) ZyXEL_1496_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
     (char *) IS_101_beep_answr,
              ZyXEL_1496_beep_timeunit,
     (char *) IS_101_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) IS_101_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) IS_101_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) ZyXEL_1496_intr_play_cmnd,
     (char *) ZyXEL_1496_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) ZyXEL_1496_stop_play_answr,
     (char *) IS_101_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) IS_101_stop_rec_cmnd,
     (char *) ZyXEL_1496_stop_rec_answr,
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
     &ZyXEL_1496_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &ZyXEL_1496_set_compression,
     &ZyXEL_1496_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &IS_101_switch_to_data_fax,
     &IS_101_voice_mode_off,
     &IS_101_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &ZyXEL_1496_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };
