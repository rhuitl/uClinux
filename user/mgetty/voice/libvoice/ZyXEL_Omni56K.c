/*
 * ZyXEL_Omni56K.c
 *
 * This file contains the ZyXEL Omni 56K specific hardware stuff.
 *
 * Based on code for Elite 2864 modems (ZyXEL_2864.c), with
 * corrections made by Const Kaplinsky <const@ce.cctpu.edu.ru>
 *
 * $Id: ZyXEL_Omni56K.c,v 1.4 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static char number[16];

static int ZyXEL_Omni56K_init (void)
     {

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing ZyXEL Omni 56K voice modem");

     /*
      * ATS40.3=1 - Enable distincitve ring type 1 (RING)
      * ATS40.4=1 - Enable distincitve ring type 2 (RING 1)
      * ATS40.5=1 - Enable distincitve ring type 3 (RING 2)
      * ATS40.6=1 - Enable distincitve ring type 4 (RING 3)
      * MUST NOT send spaces in between ATS... commands, otherwise
      * all but the first are ignored (Richard L. Hamilton)
      */

     if (voice_command("ATS40.3=1S40.4=1S40.5=1S40.6=1", "OK") !=
      VMA_USER_1)
          lprintf(L_WARN, "couldn't initialize distinctive RING");

     /*
      * Further initialization goes to ZyXEL_Omni56K_voice_mode_on()
      */

     voice_modem_state = IDLE;
     return(OK);
     }

static int ZyXEL_Omni56K_voice_mode_on (void)
     {
     char buffer[VOICE_BUF_LEN];

     if (IS_101_voice_mode_on())
          return(FAIL);

     /*
      * We perform initialization here because Omni56K
      * resets voice settings after leaving voice mode
      */

     /*
      * AT+VIT=100 - Set inactivity timer to 10 seconds
      */

     if (voice_command("AT+VIT=100", "OK") != VMA_USER_1)
          lprintf(L_WARN, "voice init failed, continuing");

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

     /* -- alborchers@steinerpoint.com
      * AT+VRA and AT+VRN - Delay after ringback or before any ringback
      *                     before modem assumes phone has been answered.
      */

     sprintf(buffer, "AT+VRA=%d+VRN=%d",
      cvd.ringback_goes_away.d.i, cvd.ringback_never_came.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN,"setting ringback delay didn't work");

     return(OK);
     }

static int ZyXEL_Omni56K_set_compression (int *compression, int *speed, int *bits)
     {

     reset_watchdog();

     /*
      * According to documentation, only 4-bit ADPCM at 9600 Hz is supported
      */

     if (*speed == 0)
          *speed = 9600;

     if (*speed != 9600)
          {
          lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name,
           *speed);
          return(FAIL);
          };

     if (*compression == 0)
          *compression = 4;

     if (*compression != 4)
          {
          lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
           voice_modem_name, *compression);
          return(FAIL);
          };

     *bits = 4;

     if (voice_command("AT+VSM=4,9600", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

static int ZyXEL_Omni56K_set_device (int device)
     {
     reset_watchdog();

     switch (device)
          {
          case NO_DEVICE:
               voice_command("AT+VLS=0", "OK");
               return(OK);

          /* For Omni 56K Plus compatibility (not tested) */
          case LOCAL_HANDSET:
               voice_command("AT+VLS=1", "VCON");
               return(OK);

          case DIALUP_LINE:
               voice_command("AT+VLS=2", "VCON");
               return(OK);
          };

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

static int ZyXEL_Omni56K_answer_phone (void)
{
  char buffer[VOICE_BUF_LEN];
  char resp[] = "CALLER'S NUMBER: ";
  int i, j, len;

  if (IS_101_answer_phone() != VMA_OK)
    return VMA_ERROR;

  if (strcmp(CallerId, "none") != 0)
    return VMA_OK;

  if (voice_command("AT*T", "") == OK && voice_read(buffer) == OK) {
    len = strlen(resp);
    if (strncmp(buffer, resp, len) == 0) {
      for (i = len, j = 0; buffer[i] && j < 15; i++) {
        if (isprint(buffer[i] & 0xFF))
          number[j++] = buffer[i];
      }
      number[j++] = '\0';
      lprintf(L_NOISE, "Got caller ID: \"%s\"", number);

      if (voice_command("AT&I0", ""))
        voice_flush(3);

      if (number[0] && strcmp(number, "?")) {
        CallerId = number;
        setup_environment();
      }
    } else {
      voice_flush(3);
    }
  }
  return VMA_OK;
}

/*
 * Of course, "AT+VLS=2" works too, but it does not activate
 * russian-style caller ID detection while "ATA" does.
 */
static char ZyXEL_Omni56K_pick_phone_cmnd[] = "ATA";

static char ZyXEL_Omni56K_pick_phone_answr[] = "VCON";

voice_modem_struct ZyXEL_Omni56K =
     {
     "ZyXEL Omni 56K",
     "ZyXEL Omni 56K",

     (char *) ZyXEL_Omni56K_pick_phone_cmnd,
     (char *) ZyXEL_Omni56K_pick_phone_answr,
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

     &ZyXEL_Omni56K_answer_phone,
     &IS_101_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &ZyXEL_Omni56K_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &ZyXEL_Omni56K_set_compression,
     &ZyXEL_Omni56K_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &IS_101_switch_to_data_fax,
     &IS_101_voice_mode_off,
     &ZyXEL_Omni56K_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &IS_101_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };
