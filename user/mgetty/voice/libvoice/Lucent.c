/*
 * Lucent.c
 *
 * This file contains the Lucent specific hardware stuff.
 *
 * $Id: Lucent.c,v 1.4 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static int Lucent_handle_dle(char data)
     {

     switch (data)
          {

	  /*
	   * It appears that Lucent modems have just a single
	   * silence detection notification, that always reports
	   * as "<DLE>-s".  This report indicates that silence
	   * exceeding the duration of the interval set with AT+VSD
	   * has been detected, regardless of whether there was
	   * previously good data or not.
	   *
	   * So here we override the IS_101 mapping of DLE-s to
	   * "NO_VOICE_ENERGY", and change it to "SILENCE_DETECTED".
	   *
	   * Caveat: this will break vgetty's heuristic "if <DLE>s
	   *  was seen, there is nobody at the calling end, so let's try
	   *  data/fax mode".  So if you have a Lucent modem and want to
	   *  do voice and data/fax on the same line, you need calling
	   *  modems that send a CNG tone, or have the caller dial up,
	   *  wait for a few seconds, and then send another DTMF tone
	   *  (which will trigger data/fax mode).
	   *
	   * Patch by Paul Fox <pgf@foxharp.boston.ma.us>
	   */
          case 's':
               return(queue_event(create_event(SILENCE_DETECTED)));

          }

     return(IS_101_handle_dle(data));
     }


static int Lucent_init (void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing Lucent voice modem");

     /*
      * AT+VSD=x,y - Set silence threshold and duration.
      */

     sprintf(buffer, "AT+VSD=%d,%d", cvd.rec_silence_threshold.d.i *
      10 / 100 + 123, cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting recording preferences didn't work");

     /*
      * AT+VGT - Set the transmit gain for voice samples.
      */

     if (cvd.transmit_gain.d.i == -1)
          cvd.transmit_gain.d.i = 128;

     sprintf(buffer, "AT+VGT=%d", cvd.transmit_gain.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting transmit gain didn't work");

     /*
      * AT+VGR - Set receive gain for voice samples.
      */

     if (cvd.receive_gain.d.i == -1)
          cvd.receive_gain.d.i = 128;

     sprintf(buffer, "AT+VGR=%d", cvd.receive_gain.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting receive gain didn't work");

     if (voice_command("AT+VIT=0", "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't deactivate inactivity timer");

     if (voice_command("AT+VPR=0", "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't select autobauding");

     if (voice_command("AT+VLS=0", "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't deselect all input/output devices");

     voice_modem_state = IDLE;
     return(OK);
     }

static int Lucent_set_compression (int *compression, int *speed, int *bits)
     {
     char buffer[VOICE_BUF_LEN];
     reset_watchdog();

     if (*compression == 0)
       *compression = 4;
     
     if (*speed == 0)
       *speed = 8000;

     switch (*compression)
          {
          case 1:
               *bits = 8;

	       if ( (*speed != 7200) && (*speed != 8000) && (*speed != 11025) )
		 {
		          lprintf(L_WARN, "%s: Illegal sample rate (%d)", 
				  voice_modem_name, *speed);
			  return(FAIL); 
		 }

	       sprintf(buffer, "AT+VSM=128,%d", *speed);
               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 2:
               *bits = 16;

	       if ( (*speed != 7200) && (*speed != 8000) && (*speed != 11025) )
		 {
		          lprintf(L_WARN, "%s: Illegal sample rate (%d)", 
				  voice_modem_name, *speed);
			  return(FAIL); 
		 }
	       
	       sprintf(buffer, "AT+VSM=129,%d", *speed);
               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 3:
               *bits = 8;

	       if ( *speed != 8000 )
		 {
		   lprintf(L_WARN, "%s: Illegal sample rate (%d)", 
				  voice_modem_name, *speed);
			  return(FAIL); 
		 }

	       sprintf(buffer, "AT+VSM=130,%d", *speed);
               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;

	  case 4:
	    *bits = 8;

	    if ( *speed != 8000 )
	      {
		lprintf(L_WARN, "%s: Illegal sample rate (%d)", 
				  voice_modem_name, *speed);
		return(FAIL); 
	      }
	    sprintf(buffer, "AT+VSM=131,%d", *speed);
	    if (voice_command(buffer, "OK") != VMA_USER_1)
	      return(FAIL);
	    
	    break;

	  case 5:
	    *bits = 4;

	    if ((*speed != 8000) && (*speed != 7200) && (*speed != 11025))
	      {
		lprintf(L_WARN, "%s: Illegal sample rate (%d)", 
				  voice_modem_name, *speed);
		return(FAIL); 
	      }

	    sprintf(buffer, "AT+VSM=132,%d", *speed);
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

static int Lucent_set_device (int device)
     {
     reset_watchdog();

     switch (device)
          {
	  case DIALUP_WITH_LOCAL_HANDSET:
          case NO_DEVICE:
               voice_command("AT+VLS=0", "OK");
               return(OK);
          case DIALUP_LINE:
               voice_command("AT+VLS=1", "OK");
               return(OK);
	  case LOCAL_HANDSET:
	    voice_command("AT+VLS=2", "OK");
	    return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT+VLS=4", "OK");
               return(OK);
          case INTERNAL_MICROPHONE:
               voice_command("AT+VLS=6", "OK");
               return(OK);
	  case DIALUP_WITH_INT_SPEAKER:
	    voice_command("AT+VLS=5", "OK");
	    return(OK);
	  case DIALUP_WITH_INTERNAL_MIC_AND_SPEAKER:
	    voice_command("AT+VLS=7", "OK");
	    return(OK);

          };

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

int Lucent_beep(int frequency, int length)
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


const char Lucent_beep_cmnd[] = "AT+VTS=[%d,%d,%d]";

voice_modem_struct Lucent =
     {
     "Venus V.90 USB U052099a",
     "Lucent",
     (char *) IS_101_pick_phone_cmnd,
     (char *) IS_101_pick_phone_answr,
     (char *) Lucent_beep_cmnd,
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
     &Lucent_beep,
     &IS_101_dial,
     &Lucent_handle_dle,
     &Lucent_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Lucent_set_compression,
     &Lucent_set_device,
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



