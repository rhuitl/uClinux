/*
 * Multitech_5634ZPX_ISA.c
 *
 * Hacked by <Harlan.Stenn@pfcs.com>. Maybe will be merged
 * with the other Multitech driver.
 *
 * $Id: Multitech_5634ZPX_ISA.c,v 1.2 2005/03/13 17:27:46 gert Exp $
 *
 * Copied by milosch 2001/11/30
 * Mostly `inherits' Multitech_5634ZPX.c
 */

#include "../include/voice.h"

/* Imported/inherited functions */
extern int Multitech_5634ZPX_answer_phone(void);
extern int Multitech_5634ZPX_init(void);
extern int Multitech_5634ZPX_set_compression(int *compression, int *speed,
					     int *bits);
extern int Multitech_5634ZPX_switch_to_data_fax(char *mode);
extern int Multitech_5634ZPX_voice_mode_off(void);
extern int Multitech_5634ZPX_voice_mode_on(void);

static int Multitech_5634ZPX_ISA_set_device(int device)
     {
     reset_watchdog();

     /*
       0,"",B0000000,B0000000,B0000000
       1,"T",0BC01800,0BC01800,0BC01800
       2,"L",00000000,00000000,B0000000
       3,"LT",0BC01800,0BC01800,0BC01800
       4,"S",00000000,00000000,B0000000
       5,"ST",0BC01800,0BC01800,0BC01800
       6,"M",00000000,00000000,B0000000
       7,"MST",0BC01800,0BC01800,0BC01800
       where:
       0 "" on-hook, local phone->telco
       1 T  off-hook, modem->telco
       2 L  off-hook, local phone->telco
       3 LT off-hook, local phone&modem->telco
       4 S  on-hook, spkr->modem, local phone->telco
       5 ST off-hook, spkr->telco, modem->telco
       6 M  on-hook, mike->modem, local phone->telco
       7 MST  off-hook, mike&spkr->telco, modem->telco
     */
     switch (device)
          {
          case NO_DEVICE:
               voice_command("AT+VLS=0", "OK");
               return(OK);
          case LOCAL_HANDSET:
               voice_command("AT+VLS=2", "OK");
               return(OK);
          case DIALUP_LINE:
               voice_command("AT+VLS=1", "OK");
               return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT+VLS=4", "OK");
               return(OK);
          case EXTERNAL_MICROPHONE:
               voice_command("AT+VLS=6", "OK");
               return(OK);
          };

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

int Multitech_5634ZPX_ISA_beep(int frequency, int length)
     {
     char buffer[VOICE_BUF_LEN];
     int true_length = length / voice_modem->beep_timeunit;

     reset_watchdog();
     sprintf(buffer, voice_modem->beep_cmnd, frequency, frequency, true_length);

     if (voice_command(buffer, "") != OK)
          return(FAIL);

     delay(((length - 1000) > 0) ? (length - 1000) : 0);

     if ((voice_command("", voice_modem->beep_answr) & VMA_USER) != VMA_USER)
          return(FAIL);

     return(OK);
     }

#define Multitech_beep_timeunit	100
static char Multitech_beep_cmnd[] = "AT+VTS=[%d,%d,%d]";

voice_modem_struct Multitech_5634ZPX_ISA =
{
     "Multitech 5634ZPX_ISA",
     "Multitech5634",
     (char *) IS_101_pick_phone_cmnd,
     (char *) IS_101_pick_phone_answr,
     (char *) Multitech_beep_cmnd,
     (char *) IS_101_beep_answr,
              Multitech_beep_timeunit,
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
     &Multitech_5634ZPX_answer_phone,
     &IS_101_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &Multitech_5634ZPX_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Multitech_5634ZPX_set_compression,
     &Multitech_5634ZPX_ISA_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &Multitech_5634ZPX_switch_to_data_fax,
     &Multitech_5634ZPX_voice_mode_off,
     &Multitech_5634ZPX_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &IS_101_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
};
