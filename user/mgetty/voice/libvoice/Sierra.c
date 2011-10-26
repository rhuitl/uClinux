/*
 * Sierra.c
 *
 * This file contains specific hardware stuff for Sierra based
 * voice modems.
 *
 * The Sierra driver is written and maintained by
 * Luke Bowker <puke@suburbia.net>.
 *
 * $Id: Sierra.c,v 1.8 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

#define Sierra_BUFFER_SIZE 255
#define ACK    0x06

static TIO tio;
static TIO Sierra_tio_save;

static int buffer_size = Sierra_BUFFER_SIZE;

int Sierra_init(void)
     {
     return(OK);
     }

static int Sierra_voice_mode_on(void)
     {
     char buffer[Sierra_BUFFER_SIZE];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing Sierra voice modem");
     tio_get(voice_fd, &tio);
     Sierra_tio_save = tio;

     /*
      * AT#VSn - Enable voice mode at bit rate n (1 = 115.2k).
      */

     if (voice_command("AT#VS1", "OK") != VMA_USER_1)
          lprintf(L_WARN, "Voice mode didn't work");

     tio_set_speed(&tio, 115200);
     tio_set(voice_fd, &tio);
     sprintf(buffer, "ATM2L3#VL=0#VSM=2#VSC=0#VSS=3#VSI=%1u",
      cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "Couldn't set voice mode options");

     sprintf(buffer, "AT#VF=0");

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "Couldn't set buffer size to %d", buffer_size);

     voice_modem_state = IDLE;
     return(OK);
     }

int Sierra_voice_mode_off(void)
     {
     reset_watchdog();

     if (voice_command("AT#VS0", "OK") != VMA_USER_1)
          return(FAIL);

     tio_set(voice_fd, &Sierra_tio_save);
     return(OK);
     }

static int Sierra_set_compression(int *compression, int *speed, int *bits)
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
          }

     if (*compression != 2)
          {
          lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
           voice_modem_name, *compression);
          return(FAIL);
          }

     *bits = 8;

     if (voice_command("AT#VSM=2", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

int Sierra_beep (int frequency, int length)
     {

     /*
      * The docs I have define a command as "AT#VB=f,t" for playing tones,
      * but I couldn't get it to work. So we'll generate one with code
      * flogged from sine.c in the libpvf code.
      */

     double freq;
     int time, i;
     char d;

     time = (9600 * length) / 1000;
     freq = (double) frequency;

     if (voice_command("AT#VSV", "CONNECT") != VMA_USER_1)
          return(FAIL);

     for(i = 0; i < time; i++)
          {
          d = (char) (i * freq / 9600) * 0x7f;
          voice_write_char(d);
          }

     voice_write_char(DLE);
     voice_write_char(ETX);

     if ((voice_command("", "OK|VCON") & VMA_USER) != VMA_USER)
          return(FAIL);

     return(OK);
     }

int Sierra_set_device(int device)
     {
     lprintf(L_WARN,
      "%s: set_device(%d) called. Doesn't achieve anything in this implementation",
      voice_modem_name, device);
     return(OK);
     }

static char Sierra_pick_phone_cmnd[] = "ATA";
static char Sierra_pick_phone_answr[] = "#VCON";
static char Sierra_hardflow_cmnd[] = "AT";
static char Sierra_softflow_cmnd[] = "AT";
static char Sierra_start_play_cmnd[] = "AT#VSV";
static char Sierra_intr_play_answr[] = "OK|VCON";
static char Sierra_stop_play_answr[] = "OK|VCON";
static char Sierra_start_rec_cmnd[] = "AT#VD1";
static char Sierra_stop_rec_answr[] = "OK|VCON";

voice_modem_struct Sierra =
     {
     "Sierra",
     "Sierra",
     (char *) Sierra_pick_phone_cmnd,
     (char *) Sierra_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
     (char *) IS_101_beep_answr,
              IS_101_beep_timeunit,
     (char *) Sierra_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) Sierra_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) Sierra_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) IS_101_intr_play_cmnd,
     (char *) Sierra_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) Sierra_stop_play_answr,
     (char *) Sierra_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) IS_101_stop_rec_cmnd,
     (char *) Sierra_stop_rec_answr,
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
     &Sierra_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &Sierra_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     NULL,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Sierra_set_compression,
     &Sierra_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &IS_101_switch_to_data_fax,
     &Sierra_voice_mode_off,
     &Sierra_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &IS_101_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };






