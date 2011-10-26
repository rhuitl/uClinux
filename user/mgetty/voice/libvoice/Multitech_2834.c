/*
 * Multitech_2834.c
 *
 * This file contains the MultiTech 2834 specific hardware stuff.
 *
 * A first version was written by Russell King <rmk@ecs.soton.ac.uk>,
 * based on the ZyXEL 2864 driver.
 *
 * $Id: Multitech_2834.c,v 1.9 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static char mode_save[16] = "";

static int Multitech_2834_answer_phone(void)
     {
     int result;

     reset_watchdog();

     if (((result = voice_command("AT+VLS=1", "OK|CONNECT")) & VMA_USER) !=
      VMA_USER)
          return(VMA_ERROR);

     if (result == VMA_USER_2)
          return(VMA_CONNECT);

     return(VMA_OK);
     }

static int Multitech_2834_init(void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing Multitech 2834 voice modem");

     /*
      * AT+VIT=10 - Set inactivity timer to 10 seconds
      */

     if (voice_command("AT+VIT=10", "OK") != VMA_USER_1)
          lprintf(L_WARN, "voice init failed, continuing");
#if 0
     /*
      * AT+VDD=x,y - Set DTMF tone detection threshold and duration detection
      */

     sprintf(buffer, "AT+VDD=%d,%d", cvd.dtmf_threshold.d.i *
      31 / 100, cvd.dtmf_len.d.i / 5);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting DTMF preferences didn't work");
#endif
     /*
      * AT+VSD=x,y - Set silence threshold and duration.
      */

     sprintf(buffer, "AT+VSD=%d,%d", /*cvd.rec_silence_threshold.d.i *
      1 / 100 +*/ 128, cvd.rec_silence_len.d.i);

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

static int Multitech_2834_set_compression(int *compression, int *speed,
 int *bits)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();

     if (*compression == 0)
          *compression = 4;

     if (*speed == 0)
          *speed = 8000;

     if (*speed != 8000)
          {
          lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name,
           *speed);
          return(FAIL);
          }

     switch (*compression)
          {
          case 4:
               *bits = 4;
               sprintf(buffer, "AT+VSM=2,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          case 132:
               *bits = 4;
               sprintf(buffer, "AT+VSM=132,%d", *speed);

               if (voice_command(buffer, "OK") != VMA_USER_1)
                    return(FAIL);

               break;
          default:
               lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
                voice_modem_name, *compression);
               return(FAIL);
          }

     return(OK);
     }

static int Multitech_2834_set_device(int device)
     {
     reset_watchdog();

     switch (device)
          {
          case NO_DEVICE:
               voice_command("AT+VLS=0", "OK");
               return(OK);
          case LOCAL_HANDSET:
               voice_command("AT+VLS=2", "OK");
               return(OK);
          case DIALUP_LINE:
               voice_command("AT+VLS=1", "OK"); /* alborchers@steinerpoint.com */
               return(OK);
          case EXTERNAL_MICROPHONE:
               voice_command("AT+VLS=11", "OK");
               return(OK);
          case INTERNAL_SPEAKER:
               voice_command("AT+VLS=4", "OK");
               return(OK);
          };

     lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
      device);
     return(FAIL);
     }

void Multitech_2834_fix_modem(int expect_error)
{
	char buffer[VOICE_BUF_LEN];
	int result = VMA_FAIL;

        if (!cvd.enable_command_echo.d.i) {
  	   /* Multitech 2834 ZDXV modem (ROM 0416A NORTH AMERICAN) 
            * -- alborchers@steinerpoint.com
            *    As I understand the problem -- some Multitech 2834 ZDXv
            *    modems garble the command echo at certain points. To counter
            *    this, a dummy command is sent at those points (just AT)
            *    and the echo is ignored: this is the purpose of
            *    Multitech_2834_fix_modem(). If echo is off, there is
            *    no need to prevent garbled commands echos, and thus no need
            *    for Multitech_2834_fix_modem() (in fact, it would fail).
            */

           return; 
        }

	/* my ZDXv with 0416A firmware seems to exhibit a bug here -
	 * if you send the modem 'AT', it echos 'TA'.  If you send it
	 * 'ATI', it echos 'TIA'!
	 */
	voice_write("AT");
	do {
		if (voice_read(buffer) != OK) {
			voice_flush(1);
			break;
		}

		result = voice_analyze(buffer, "AT", TRUE);

		if (result == VMA_FAIL) {
			voice_flush(1);
			break;
		}

		if (result == VMA_ERROR) {
			lprintf(L_WARN, "%s: Modem returned ERROR",
	        		program_name);
			voice_flush(1);
			break;
		}
	} while (result != VMA_USER_1);

	if (result == VMA_USER_1 && expect_error)
        	lprintf(L_WARN, "%s: Modem answered correctly - mail rmk@arm.uk.linux.org",
        		program_name);
        if (result != VMA_USER_1 && !expect_error)
        	lprintf(L_WARN, "%s: Modem answered incorrectly - mail rmk@arm.uk.linux.org",
			program_name); 
}

static int Multitech_2834_switch_to_data_fax(char *mode)
{
	char buffer[VOICE_BUF_LEN];

	sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd, mode);

	if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
	    VMA_USER)
		return FAIL;

	Multitech_2834_fix_modem(1);

	return OK;
}

static int Multitech_2834_voice_mode_off(void)
{
	char buffer[VOICE_BUF_LEN];

	sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd, mode_save);

	if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
	    VMA_USER)
		return FAIL;

	Multitech_2834_fix_modem(1);

	return OK;
}

static int Multitech_2834_voice_mode_on(void)
{
	char buffer[VOICE_BUF_LEN];

	if (voice_command(voice_modem->ask_mode_cmnd, "") != OK)
		return FAIL;

	do {
		if (voice_read(mode_save) != OK)
			return FAIL;
	} while (strlen(mode_save) == 0);

	if (strncmp(mode_save, "+FCLASS=", 8) == 0)
        	memmove(mode_save, mode_save + 8, strlen(mode_save) - 8 + 1);

	if ((voice_command("", voice_modem->ask_mode_answr) & VMA_USER) != VMA_USER)
		return FAIL;

	sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd,
		voice_modem->voice_mode_id);

	if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
	    VMA_USER)
		return FAIL;

	Multitech_2834_fix_modem(0);

	return OK;
}

#define Multitech_beep_timeunit	100

voice_modem_struct Multitech_2834ZDXv =
     {
     "Multitech 2834ZDXv",
     "Multitech2834",
     (char *) IS_101_pick_phone_cmnd,
     (char *) IS_101_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
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

     &Multitech_2834_answer_phone,
     &IS_101_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &Multitech_2834_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Multitech_2834_set_compression,
     &Multitech_2834_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &Multitech_2834_switch_to_data_fax,
     &Multitech_2834_voice_mode_off,
     &Multitech_2834_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &IS_101_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };





