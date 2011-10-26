/*
 * Umc.c
 *
 * This file contains the UMC UM92144EF specific hardware stuff.
 * (e.g. Creatix PhoneMaster 144VFi)
 *
 * This file was originally written by Ulrich Homann <ulho@uni-paderborn.de>.
 *
 * Creatix Phonemaster 144VFi for sale (cheap&nasty UMC based Modem)
 *   contact me!
 *
 * New updated driver by Jens Adner <Jens.Adner@Wirtschaft.TU-Ilmenau.DE>.
 *
 * $Id: UMC.c,v 1.10 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

#define UMC_RELEASE "0.02"
/* #define UMC_VTS_WORKAROUND yes */
/* #define UMC_EXTENDED_DETECTION yes */
#define UMC_SPEAKER_ON yes
/* workaround: it should set by vgetty
 * ! program_name must be vgetty !
 */

/*
 * Internal status variables for aborting some voice modem actions.
 */

static int current_device=-1;

static int UMC_init(void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     lprintf(L_MESG, "initializing UMC voice modem");
     voice_modem_state = INITIALIZING;
     sprintf(buffer, "AT#VSP=%1u", cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence period");

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

     if (voice_command("AT\\Q3", "OK") == VMA_USER_1)
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

static int UMC_set_compression(int *compression, int *speed, int *bits)
     {
     reset_watchdog();

     if (*compression == 0)
          *compression = 4;

     if (*speed == 0)
          *speed = 7200;

     switch (*compression)
          {
          case 2:
               *bits=2;

               if (voice_command("AT#VBS=2", "OK") != VMA_USER_1)
                    return(FAIL);

               return (OK);
          case 3:
               *bits=3;

               if (voice_command("AT#VBS=3", "OK") != VMA_USER_1)
                    return(FAIL);

               return (OK);
          case 4:
               *bits=4;

               if (voice_command("AT#VBS=4", "OK") != VMA_USER_1)
                    return(FAIL);

               return (OK);
          }

     lprintf(L_WARN,
      "UMC handle event: Illegal voice compression method (%d)",
      *compression);
     return(FAIL);
     }

static int UMC_set_device(int device)
     {
     reset_watchdog();

     if ((current_device != device) && (current_device >= 0))
          voice_command("ATH0","VCON|OK");

     current_device=device;

     /* Sending a ATH0 results in leaving voice mode.
      * The UMC modem reports ERROR if an AT#VLS command is issued while not
      * beeing in voice mode.
      * Thus this force into voice mode.
      * -- steffen@informatik.tu-darmstadt.de
      */
     voice_command("AT#CLS=8", "OK");

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
          /* case SPEAKER_PHONE_MODE:
           *    voice_command("AT#VLS=6","OK");
           *    return(OK);
           */
          }

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

static int UMC_beep(int frequency, int length)
     {
#ifdef UMC_VTS_WORKAROUND
     /*
      * generate a beep with 900Hz
      * sorry: just a near miss.
      */

     TIO tio;
     char *sinewave="\x37\x8c\xc8\x73";
     int sinelen=4;
     int i;

     tio_get(voice_fd, &tio);
     tio_set_flow_control(voice_fd, &tio, FLOW_HARD);
     tio_set(voice_fd, &tio);

     voice_command("AT#VBS=4", "OK");
     voice_command("AT#VTX", "CONNECT");

     lprintf(L_JUNK, "%s->%s: sinewave", program_name, voice_modem_name);

     for (i=length; i>0; i--)
          {

          if (write(voice_fd,sinewave,sinelen) != sinelen)
               lprintf(L_WARN, "%s->%s: write error (errno 0x%x)",
                program_name, voice_modem_name, errno);

          }

     lprintf(L_JUNK, "%s->%s: <DLE> <ETX>", program_name, voice_modem_name);

     if (write(voice_fd, dletx , 2) != 2)
          lprintf(L_WARN, "%s->%s: write error (errno 0x%x)",
           program_name, voice_modem_name, errno);

     tio_set(voice_fd, &voice_tio);
     voice_command("", "VCON");
#else
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     if (length > 4000 )
          lprintf(L_WARN, "%s->%s: Warning beeps longer than 4000 ms might not be supported.",
	   program_name, voice_modem_name);

     lprintf(L_JUNK, "%s->%s: Some UMC modems beep with fixed frequency. This is a not a software bug.",
      program_name, voice_modem_name);

     sprintf(buffer, "AT#VTS=[%d,0,%d]", frequency, length / 100);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          return(FAIL);
#endif
     return(OK);
     }

int UMC_switch_to_data_fax(char *mode)
     {
     char buffer[VOICE_BUF_LEN];
     reset_watchdog();
     sprintf(buffer, "AT#CLS=%s", mode);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

static char UMC_pick_phone_cmnd[] = "ATA";
static char UMC_pick_phone_answr[] = "VCON";
static char UMC_hardflow_cmnd[] = "AT\\Q3";
static char UMC_softflow_cmnd[] = "AT\\Q1";
static char UMC_start_play_cmnd[] = "AT#VTX";
static char UMC_intr_play_answr[] = "OK|VCON";
static char UMC_stop_play_answr[] = "OK|VCON";
static char UMC_start_rec_cmnd[] = "AT#VRX";
static char UMC_stop_rec_cmnd[] = "!";
static char UMC_stop_rec_answr[] = "OK|VCON";
static char UMC_switch_mode_cmnd[] = "AT#CLS=";
static char UMC_ask_mode_cmnd[] = "AT#CLS?";

voice_modem_struct UMC =
     {
     "UMC",
     "UMC",
     (char *) UMC_pick_phone_cmnd,
     (char *) UMC_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
     (char *) IS_101_beep_answr,
              IS_101_beep_timeunit,
     (char *) UMC_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) UMC_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) UMC_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) IS_101_intr_play_cmnd,
     (char *) UMC_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) UMC_stop_play_answr,
     (char *) UMC_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) UMC_stop_rec_cmnd,
     (char *) UMC_stop_rec_answr,
     (char *) UMC_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) UMC_ask_mode_cmnd,
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
     &UMC_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &UMC_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     NULL,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &UMC_set_compression,
     &UMC_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &UMC_switch_to_data_fax,
     &IS_101_voice_mode_off,
     &IS_101_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &IS_101_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     VMQ_NEEDS_SET_DEVICE_BEFORE_ANSWER /* steffen@informatik.tu-darmstadt.de */
     };




