/*
 * Cirrus_Logic.c
 *
 * This file contains specific hardware stuff for Cirrus Logic based
 * voice modems. As I have NO manuals whatsovere, I sat down and reverse
 * engineered this file by capturing the o/p from my supplied Windoze
 * program (which shall remain unnamed lest I get sued :-) It works quite
 * well for me so far.
 *
 * This was written for my Cirrus Logic PCMCIA Modem which is packaged as
 * a Dynalink V1414VC modem. My ROM id shows
 *   ATI0 = 1.04
 *   ATI1 = HD94-HM71-HEC17
 *   ATI3 = CL-MD1414AT/EC
 *   ATI4 = 31
 *
 * It should work with most CL modems. Please let me know if you have
 * any problems with it. - Mitch <Mitch.DSouza@NetComm.IE>
 *
 * Modifications for the new interface were made by Hitesh K. Soneji
 * email: hitesh.soneji@industry.net
 * www:   http://www.geocities.com/SiliconValley/4548
 *
 * Brian King <Brian.Knight@fal.ca> kindly sent me a Cirrus Logic Doc with
 * all the commands for CL modems and I have made some slight changes. The
 * rec_compression parameter in voice.conf can now be 1 (default), 3 or 4
 * as per the spec. The silence threshold and time was wrongly set. Fixed now.
 * - Mitch DSouza <Mitch.DSouza@Uk.Sun.COM>
 *
 * $Id: Cirrus_Logic.c,v 1.8 2005/03/13 17:27:45 gert Exp $
 *
 */

#include "../include/voice.h"

/*
 * Here we save the current mode of operation of the voice modem when
 * switching to voice mode, so that we can restore it afterwards.
 */

static char cirrus_logic_ans[VOICE_BUF_LEN] = "";

typedef struct
     {
     int min;
     int max;
     } range;

/*
 * Get Range
 * This Function is only for Cirrus Logic
 */

static void get_range(char *buf, range *r)
     {

     if ((!buf) || (!r))
          return;

     sscanf(buf, "(%d-%d)", &r->min, &r->max);
     }

int Cirrus_Logic_answer_phone (void)
     {
     reset_watchdog();
     lprintf(L_MESG, "Answering Call");

     if (voice_command("AT#VLN=1", "OK") != VMA_USER_1)
          return(VMA_ERROR);

     if (voice_command("AT#VIP=1", "OK") != VMA_USER_1)
          return(VMA_ERROR);

     return(VMA_OK);
     }

int Cirrus_Logic_beep (int frequency, int length)
     {
     char buffer[VOICE_BUF_LEN];
     int watchdog_count = 0;

     reset_watchdog();
     sprintf(buffer, "AT#VBP");
     lprintf(L_MESG, "Checking Beep");

     if (voice_command(buffer, "") != OK)
          return(FAIL);

     while (!check_for_input(voice_fd))
          {
          
          if ((watchdog_count--) <= 0)
               {
               reset_watchdog();
               watchdog_count = cvd.watchdog_timeout.d.i * 1000 /
                cvd.poll_interval.d.i / 2;
               }

          delay(cvd.poll_interval.d.i);
          }

     if (voice_command("", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

int Cirrus_Logic_init (void)
     {
     char buffer[VOICE_BUF_LEN];
     range play_range = {0, 0};
     range rec_range = {0, 0};
     range rec_silence_threshold = {0, 0};

     reset_watchdog();
     lprintf(L_MESG, "Initializing Cirrus Logic voice modem");
     voice_modem_state = INITIALIZING;

     /* Get the record volume range available from modem */
     voice_command("AT#VRL=?", "");
     voice_read(cirrus_logic_ans);
     voice_flush(1);
     get_range(cirrus_logic_ans, &rec_range);

     if (cvd.receive_gain.d.i == -1)
          cvd.receive_gain.d.i = (rec_range.max + rec_range.min) / 2;

     sprintf(buffer, "AT#VRL=%.0f", rec_range.min + ((rec_range.max -
      rec_range.min) * cvd.receive_gain.d.i / 100.0));

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set recording volume");

     /* Get the play volume range available from modem */
     voice_command("AT#VPL=?", "");
     voice_read(cirrus_logic_ans);
     voice_flush(1);
     get_range(cirrus_logic_ans, &play_range);

     if (cvd.transmit_gain.d.i == -1)
          cvd.transmit_gain.d.i = (play_range.max + play_range.min) / 2;

     sprintf(buffer, "AT#VPL=%.0f", play_range.min + ((play_range.max -
      play_range.min) * cvd.transmit_gain.d.i / 100.0));

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set play volume");

     if ((cvd.rec_silence_threshold.d.i > 100) ||
        (cvd.rec_silence_threshold.d.i < 0))
          {
          lprintf(L_WARN, "Invalid threshold value.");
          return(ERROR);
          }

     /* Get the silence threshold range from modem */
     voice_command("AT#VSL=?", "");
     voice_read(cirrus_logic_ans);
     voice_flush(1);
     get_range(cirrus_logic_ans, &rec_silence_threshold);

     sprintf(buffer, "AT#VSL=%.0f", rec_silence_threshold.min +
      ((rec_silence_threshold.max - rec_silence_threshold.min) *
      cvd.rec_silence_threshold.d.i / 100.0));

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence threshold");

     sprintf(buffer, "AT#VSQT=%1u", cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence period record mode");

     sprintf(buffer, "AT#VSST=%1u", cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence period record and command mode");

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

/*
 * As far as my specs go the CL modem only supports a sample rate of 9600 at
 * 5, 3 or 4 bits.
 */

static int Cirrus_Logic_set_compression (int *compression, int *speed,
 int *bits)
     {
     lprintf(L_MESG, "Setting compression");
     reset_watchdog();

     if (*compression == 0)
          *compression = 1;

     if (*speed == 0)
          *speed = 9600;

     if (*speed != 9600)
          {
          lprintf(L_WARN, "%s: Illegal sample speed (%d)",
           voice_modem_name, *speed);
          return(FAIL);
          }

     voice_command("AT#VSR=9600", "OK");

     switch (*compression)
          {
          case 3:
               voice_command("AT#VSM=AD3", "OK");
               *bits = 3;
               return(OK);
          case 4:
               voice_command("AT#VSM=AD4", "OK");
               *bits = 4;
               return(OK);
          default:
               voice_command("AT#VSM=CL1", "OK");
               *bits = 5;
               return(OK);
          }

     return(OK);
     }

int Cirrus_Logic_set_device (int device)
     {
     reset_watchdog();
     lprintf(L_MESG, "Setting device");

     switch (device)
          {
          case NO_DEVICE:
               voice_command("AT#VLN=0", "OK");
               return(OK);
          case DIALUP_LINE:
               voice_command("AT#VLN=1", "OK");
               return(OK);
          case EXTERNAL_MICROPHONE:
               voice_command("AT#VLN=32", "OK");
               return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT#VLN=16", "OK");
               return(OK);
          case LOCAL_HANDSET:
               voice_command("AT#VLN=2","OK");
               return(OK);
          }

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

int Cirrus_Logic_switch_to_data_fax (char *mode)
     {
     char buffer[VOICE_BUF_LEN];

     lprintf(L_MESG, "Switching to data/fax");
     reset_watchdog();
     sprintf(buffer, "AT+FCLASS=%s", mode);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

static char Cirrus_Logic_hardflow_cmnd[] = "AT";
static char Cirrus_Logic_softflow_cmnd[] = "AT";
static char Cirrus_Logic_start_play_cmnd[] = "AT#VPY";
static char Cirrus_Logic_intr_play_cmnd[] = {DLE, 'A', DLE, ETX, 0x00};
static char Cirrus_Logic_intr_play_answr[] = "OK|VCON";
static char Cirrus_Logic_stop_play_answr[] = "OK|VCON";
static char Cirrus_Logic_start_rec_cmnd[] = "AT#VRD";
static char Cirrus_Logic_stop_rec_cmnd[] = {CR, 0x00};
static char Cirrus_Logic_stop_rec_answr[] = "OK|VCON";
static char Cirrus_Logic_switch_mode_cmnd[] = "AT#VCL=";
static char Cirrus_Logic_ask_mode_cmnd[] = "AT#VCL?";
static char Cirrus_Logic_voice_mode_id[] = "1";

voice_modem_struct Cirrus_Logic =
     {
     "Cirrus Logic",
     "Cirrus Logic",
     (char *) IS_101_pick_phone_cmnd,
     (char *) IS_101_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
     (char *) IS_101_beep_answr,
              IS_101_beep_timeunit,
     (char *) Cirrus_Logic_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) Cirrus_Logic_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) Cirrus_Logic_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) Cirrus_Logic_intr_play_cmnd,
     (char *) Cirrus_Logic_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) Cirrus_Logic_stop_play_answr,
     (char *) Cirrus_Logic_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) Cirrus_Logic_stop_rec_cmnd,
     (char *) Cirrus_Logic_stop_rec_answr,
     (char *) Cirrus_Logic_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) Cirrus_Logic_ask_mode_cmnd,
     (char *) IS_101_ask_mode_answr,
     (char *) Cirrus_Logic_voice_mode_id,
     (char *) IS_101_play_dtmf_cmd,
     (char *) IS_101_play_dtmf_extra,
     (char *) IS_101_play_dtmf_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     NULL,  /* (char *) V253modem_start_duplex_voice_cmnd, */
     NULL,  /* (char *) V253modemstart_duplex_voice_answr, */
     NULL,  /* (char *) V253modem_stop_duplex_voice_cmnd , */
     NULL,  /* (char *) V253modem_stop_duplex_voice_answr, */
     // juergen.kosel@gmx.de : voice-duplex-patch end

     &Cirrus_Logic_answer_phone,
     &Cirrus_Logic_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &Cirrus_Logic_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     NULL,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Cirrus_Logic_set_compression,
     &Cirrus_Logic_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &Cirrus_Logic_switch_to_data_fax,
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
