/*
 * ISDN4Linux.c
 *
 * This file contains the ISDN4Linux specific hardware stuff.
 *
 * Bjarne Pohlers <bjarne@math.uni-muenster.de> wrote this driver and
 * maintains it. It is based on the old driver by Fritz Elfert
 * <fritz@wuemaus.franken.de> and the generic hardware driver in
 * IS_101.c
 *
 * Release Notes: You should use a recent version of the ISDN. I
 * recommend kernel 2.0.29 with patches isdn4kernel2.0.29,
 * isdn4kernel2.0.29.1, isdn4kernel2.0.29.2, isdn4kernel2.0.29.3 and
 * isdn4kernel2.0.29.4 (see ftp://ftp.franken.de/pub/isdn4linux) or
 * any later version. Older Kernels might work, but you might run in
 * trouble because of the short RING intervals there.
 *
 * I suggested in previous releases to set
 *   rec_compression 6
 *   raw_data true
 * in voice.conf as I did not test anything else. However,
 * rec_compression works fine and (in order to save disk space) you
 * should now set rec_compression to 2,3 or 4 and raw_data to false.
 *
 * You can convert your old raw audio files with the command
 * sox -tul -r 8000 INFILE -tau - | autopvf -8 | pvftormd ISDN4Linux NR >OUTFILE
 * to the new format. NR is the compression method (2,3 or 4) which needs not
 * necessarily be the same as you selected in voice.conf.
 *
 * To play a recorded file use the command
 * rmdtopvf <FILENAME | pvftoau >/dev/audio
 *
 * In mgetty.config there should be an init-chat-string for each port
 * similar to the following one:
 *   init-chat "" ATZ\d OK AT&E<Your MSN> OK
 * If you add
 *   ATS18=1 OK
 * there your isdn-tty won't pick up data calls.
 *
 * $Id: ISDN4Linux.c,v 1.10 2005/03/13 17:27:45 gert Exp $
 * 
 */

#include "../include/voice.h"
     // juergen.kosel@gmx.de : voice-duplex-patch start
#include "../include/V253modem.h" /* for duplex voice */
     // juergen.kosel@gmx.de : voice-duplex-patch end

static int is_voicecall;
static int got_DLE_DC4 = FALSE;

/*
 * This function handles the <DLE> shielded codes.
 */

int ISDN4Linux_handle_dle(char data)
     {
     switch (data)
        {
        case DC4:
             lprintf(L_WARN, "%s: <DLE> <DC4> received", program_name);
             voice_stop_current_action();
             
             switch (voice_command("", "OK|VCON|NO CARRIER"))
                  {
                  case VMA_USER_3:
                       queue_event(create_event(NO_CARRIER));
                       break;
                  case VMA_USER_1:
                  case VMA_USER_2:
                       break;
                  default:
                       return FAIL;
                  }
             
             got_DLE_DC4 = TRUE;
             return (OK);

        case ETX:
             lprintf(L_WARN, "%s: <DLE> <ETX> received", program_name);
             voice_stop_current_action();
             
             switch (voice_command("", "OK|VCON|NO CARRIER"))
                  {
                  case VMA_USER_3:
                       queue_event(create_event(NO_CARRIER));
                       break;
                  case VMA_USER_1:
                  case VMA_USER_2:
                       break;
                  default:
                       return FAIL;
                  }
             
             return (OK);
             
        default:
             return(IS_101_handle_dle(data));
        }
     }

static int ISDN4Linux_answer_phone(void)
     {
     int result;

     reset_watchdog();

     /* Check call-type:
      * S20 = 1 -> voice call
      * S20 = 4 -> data call
      */

     result = voice_command("ATS20?", "0|1|2|3|4");
     is_voicecall = (result==VMA_USER_2);

     if (is_voicecall)
          return(IS_101_answer_phone());

     return(VMA_CONNECT);
     }

static int ISDN4Linux_init(void)
     {
     static char buffer[VOICE_BUF_LEN] = "";
     unsigned reg_content;

     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing ISDN4Linux voice mode");
     reset_watchdog();

     /* Enable voice calls (set bit 1 in register S18) */

     if (voice_command("ATS18?", "") != OK)
          return(FAIL);

     if (voice_read(buffer) != OK)
          return(FAIL);

     if (voice_command("", "OK") != VMA_USER_1)
          return(FAIL);

     reg_content=atoi(buffer);

     sprintf(buffer, "ATS18=%u", reg_content | 1);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          return(FAIL);

     /* Enable CALLER NUMBER after first RING (set bit 4 in register S13) */

     if (voice_command("ATS13?", "") != OK)
          return(FAIL);

     if (voice_read(buffer) != OK)
          return(FAIL);

     if (voice_command("", "OK") != VMA_USER_1)
          return(FAIL);

     reg_content=atoi(buffer);

     sprintf(buffer, "ATS13=%u", reg_content | (1 << 4));

     if (voice_command(buffer, "OK") != VMA_USER_1)
          return(FAIL);

#if ISDN_FUTURE
     {
     char buffer[VOICE_BUF_LEN];

     /*
      * ATS40.3=1 - Enable distincitve ring type 1 (RING)
      * ATS40.4=1 - Enable distincitve ring type 2 (RING 1)
      * ATS40.5=1 - Enable distincitve ring type 3 (RING 2)
      * ATS40.6=1 - Enable distincitve ring type 4 (RING 3)
      */

     /*
      * AT+VSD=x,y - Set silence threshold and duration.
      */

     sprintf(buffer, "AT+VSD=%d,%d", cvd.rec_silence_threshold.d.i * 31 / 100,
      cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting recording preferences didn't work");

     }
#endif /* ISDN_FUTURE */

     voice_modem_state = IDLE;
     return(OK);
     }

static int ISDN4Linux_beep(int frequency, int length)
     {
#ifdef ISDN_FUTURE
     return(IS_101_beep(frequency, length));
#endif
     return(OK);
     }

static int ISDN4Linux_set_compression(int *compression, int *speed, int *bits)
     {
     char buffer[VOICE_BUF_LEN];
     reset_watchdog();

     if (*compression == 0)
          *compression = 2;

     *speed = 8000;

     switch (*compression)
          {
          case 2:
               *bits = 2;

               if (voice_command("AT+VSM=2", "OK") != VMA_USER_1)
                    return(FAIL);

               return(OK);
          case 3:
               *bits = 3;

               if (voice_command("AT+VSM=3", "OK") != VMA_USER_1)
                    return(FAIL);

               return(OK);
          case 4:
               *bits = 4;

               if (voice_command("AT+VSM=4", "OK") != VMA_USER_1)
                    return(FAIL);

               return(OK);
          case 5:
          case 6:
               *bits = 8;

               sprintf(buffer,"AT+VSM=%d",*compression);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               return(OK);
          }

     lprintf(L_WARN,
      "ISDN4Linux handle event: Illegal voice compression method (%d)",
      *compression);
     return(FAIL);
     }

static int ISDN4Linux_set_device(int device)
     {
     int result;
     reset_watchdog();

     switch (device)
          {
          case NO_DEVICE:
               voice_write("AT+VLS=0");
               result = voice_command("", "OK|NO CARRIER|AT+VLS=0");

               if (result == VMA_USER_3)
                    result = voice_command("", "OK|NO CARRIER");

               switch(result)
                    {
                    case VMA_USER_2:
                         queue_event(create_event(NO_CARRIER));
                         /* Fall through */
                    case VMA_USER_1:
                         return (OK);
                    }

               return(FAIL);
          case DIALUP_LINE:

               switch (voice_command("AT+VLS=2", "VCON|OK|NO CARRIER"))
                    {
                    case VMA_USER_3:
                         queue_event(create_event(NO_CARRIER));
                         /* Fall through */
                    case VMA_USER_1:
                    case VMA_USER_2:
                         return(OK);
                    }

               return(FAIL);
          }

     lprintf(L_WARN, "ISDN4Linux handle event: Unknown output device (%d)",
      device);
     return(FAIL);
     }

int ISDN4Linux_start_play_file(void)
     {
     voice_modem_state = PLAYING;

     if (!is_voicecall)
          return(queue_event(create_event(DATA_CALLING_TONE)));

     return(IS_101_start_play_file());
     }

int ISDN4Linux_play_file(FILE *fd, int bps)
     {

     if (!is_voicecall)
          return(queue_event(create_event(DATA_CALLING_TONE)));

     return(IS_101_play_file(fd, bps));
     }

int ISDN4Linux_dial(char *number)
     {
     int result;

     is_voicecall = FALSE;

     /* Set Service-Octet-1 to audio */

     if (voice_command("ATS18=1", "OK") != VMA_USER_1)
          return(FAIL);

     result = IS_101_dial(number);

     if (result == OK)
          is_voicecall = TRUE;

     return(result);
     }

static char ISDN4Linux_pick_phone_cmnd[] = "ATA";
static char ISDN4Linux_pick_phone_answr[] = "VCON";
#define     ISDN4Linux_beep_timeunit 100
static char ISDN4Linux_hardflow_cmnd[] = "AT";
static char ISDN4Linux_softflow_cmnd[] = "AT";
static char ISDN4Linux_start_play_answer[] = "CONNECT|NO ANSWER";
static char ISDN4Linux_intr_play_cmnd[] = {DLE, ETX, 0x00};
static char ISDN4Linux_intr_play_answr[] = "OK|VCON";
static char ISDN4Linux_stop_play_answr[] = "OK|VCON";
static char ISDN4Linux_start_rec_answr[] = "CONNECT|NO ANSWER";
static char ISDN4Linux_stop_rec_cmnd[] = {DLE, DC4, 0x00};
static char ISDN4Linux_stop_rec_answr[] = "";
// juergen.kosel@gmx.de : voice-duplex-patch start
static char ISDN4Linux_start_duplex_voice_cmnd [] = "AT+VTX+VTR"; /* so says the isdn4linux docu */
static char ISDN4Linux_stop_duplex_voice_cmnd [] = {DLE, DC4,DLE, ETX, 0x00};
// juergen.kosel@gmx.de : voice-duplex-patch end

voice_modem_struct ISDN4Linux =
     {
     "Linux ISDN",
     "ISDN4Linux",
     (char *) ISDN4Linux_pick_phone_cmnd,
     (char *) ISDN4Linux_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
     (char *) IS_101_beep_answr,
              ISDN4Linux_beep_timeunit,
     (char *) ISDN4Linux_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) ISDN4Linux_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) IS_101_start_play_cmnd,
     (char *) ISDN4Linux_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) ISDN4Linux_intr_play_cmnd,
     (char *) ISDN4Linux_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) ISDN4Linux_stop_play_answr,
     (char *) IS_101_start_rec_cmnd,
     (char *) ISDN4Linux_start_rec_answr,
     (char *) ISDN4Linux_stop_rec_cmnd,
     (char *) ISDN4Linux_stop_rec_answr,
     (char *) IS_101_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) IS_101_ask_mode_cmnd,
     (char *) IS_101_ask_mode_answr,
     (char *) IS_101_voice_mode_id,
     (char *) IS_101_play_dtmf_cmd,
     (char *) IS_101_play_dtmf_extra,
     (char *) IS_101_play_dtmf_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     (char *) ISDN4Linux_start_duplex_voice_cmnd,
     (char *) V253modemstart_duplex_voice_answr,
     (char *) ISDN4Linux_stop_duplex_voice_cmnd,
     (char *) V253modem_stop_duplex_voice_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch end

     &ISDN4Linux_answer_phone,
     &ISDN4Linux_beep,
     &ISDN4Linux_dial,
     &ISDN4Linux_handle_dle,
     &ISDN4Linux_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     NULL,
     &IS_101_stop_play_file,
     &ISDN4Linux_play_file,
     &IS_101_record_file,
     &ISDN4Linux_set_compression,
     &ISDN4Linux_set_device,
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
     &V253modem_handle_duplex_voice,
     &V253modem_stop_duplex,
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };
