/*
 * ZyXEL_2864.c
 *
 * This file contains the ZyXEL 2864 specific hardware stuff.
 *
 * A first version was written by Martin Seine <martin@erde.gun.de>,
 * that used the 1496 compatible mode of the Elite.
 *
 * This version is a complete rewrite to use the IS 101 mode of the
 * Elite 2864.
 *
 * $Id: ZyXEL_2864.c,v 1.8 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

extern int ZyXEL_1496_check_rmd_adequation(char *rmd_name);

static int ZyXEL_2864_answer_phone (void)
     {
     int result;

     reset_watchdog();

     if (((result = voice_command("AT+VLS=2", "OK|CONNECT*")) & VMA_USER) !=
      VMA_USER)
          return(VMA_ERROR);

     if (result == VMA_USER_2)
          return(VMA_CONNECT);

     return(VMA_OK);
     }

static int ZyXEL_2864_init (void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing ZyXEL 2864 voice modem");

     /*
      * Switch to IS 101 mode
      */

     if (voice_command("ATS48.5=1", "OK") != VMA_USER_1)
          lprintf(L_WARN, "couldn't set IS 101 compatible mode");

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
      * AT+VIT=100 - Set inactivity timer to 10 seconds
      */

     if (voice_command("AT+VIT=100", "OK") != VMA_USER_1)
          lprintf(L_WARN, "voice init failed, continuing");

     /*
      * AT+VDD=x,y - Set DTMF tone detection threshold and duration detection
      */

     sprintf(buffer, "AT+VDD=%d,%d", cvd.dtmf_threshold.d.i *
      15 / 100, cvd.dtmf_len.d.i / 5);

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
          cvd.transmit_gain.d.i = 50;

     sprintf(buffer, "AT+VGT=%d", cvd.transmit_gain.d.i * 144 / 100 +
      56);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting transmit gain didn't work");

     /*
      * AT+VGR - Set receive gain for voice samples.
      */

     if (cvd.receive_gain.d.i == -1)
          cvd.receive_gain.d.i = 50;

     sprintf(buffer, "AT+VGR=%d", cvd.receive_gain.d.i * 144 / 100 +
      56);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting receive gain didn't work");

     voice_modem_state = IDLE;
     return(OK);
     }

static int ZyXEL_2864_set_compression (int *compression, int *speed, int *bits)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();

     if (*compression == 0)
          *compression = 2;

     if (*speed == 0)
          *speed = 9600;

     if ((*speed != 7200) && (*speed != 8000) && (*speed != 9600) &&
      (*speed != 11025))
          {
          lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name,
           *speed);
          return(FAIL);
          };

     switch (*compression)
          {
          case 2:
               *bits = 2;
               sprintf(buffer, "AT+VSM=2,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 3:
               *bits = 3;
               sprintf(buffer, "AT+VSM=3,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 30:
               *bits = 3;
               sprintf(buffer, "AT+VSM=30,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 4:
               *bits = 4;
               sprintf(buffer, "AT+VSM=4,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 40:
               *bits = 4;
               sprintf(buffer, "AT+VSM=40,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 80:
               *bits = 8;
               sprintf(buffer, "AT+VSM=80,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 81:
               *bits = 8;
               sprintf(buffer, "AT+VSM=81,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          default:
               lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
                voice_modem_name, *compression);
               return(FAIL);
          };


     return(OK);
     }

static int ZyXEL_2864_set_device (int device)
     {
     reset_watchdog();

     switch (device)
          {
          case NO_DEVICE:
               voice_command("AT+VLS=0", "OK");
               return(OK);
          case LOCAL_HANDSET:
               voice_command("AT+VLS=1", "OK");
               return(OK);
          case DIALUP_LINE:
          
               if (voice_command("AT+VLS=2", "OK|CONNECT*") == VMA_USER_2)
                    return(VMA_CONNECT);
                    
               return(OK);
          case EXTERNAL_MICROPHONE:
               voice_command("AT+VLS=8", "OK");
               return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT+VLS=16", "OK");
               return(OK);
          };

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

voice_modem_struct ZyXEL_2864 =
     {
     "ZyXEL 2864",
     "ZyXEL 2864",
     (char *) IS_101_pick_phone_cmnd,
     (char *) IS_101_pick_phone_answr,
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

     &ZyXEL_2864_answer_phone,
     &IS_101_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &ZyXEL_2864_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &ZyXEL_2864_set_compression,
     &ZyXEL_2864_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &IS_101_switch_to_data_fax,
     &IS_101_voice_mode_off,
     &IS_101_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &ZyXEL_1496_check_rmd_adequation, /* inheritance */
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };
