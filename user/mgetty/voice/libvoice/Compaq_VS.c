/*
 * Compaq_VS.c
 * v0.01 APLHA (though it works well for me?)
 * Jesse Adam Kozloski <jakozlos@uncg.edu>
 *
 * This file contains hardware driver functions specific to the
 * Compaq VS192 (and VS288, but I don't have ATI output for that) 
 * voice modem. The docs say it is IS-101 compliant, so this shouldn't 
 * be extremely difficult.
 * 
 * These voice modems are found in the Compaq Presario 72xx and 92xx 
 * series, and maybe others as well.
 *
 * TODO: implement other voice compression modes supported by modem
 *       add other IS-101 analog source/destination configurations (?)
 *
 * $Id: Compaq_VS.c,v 1.4 2005/03/13 17:27:45 gert Exp $
 *
 */

#include "../include/voice.h"

static int Compaq_VS_answer_phone(void) 
     {
	int result;
	
	reset_watchdog();

     if(((result = voice_command(voice_modem->pick_phone_cmnd,
      voice_modem->pick_phone_answr)) & VMA_USER) != VMA_USER)
	     return(VMA_ERROR);
	
	if(result == VMA_USER_2)
	     return(VMA_CONNECT);
	
	return(VMA_OK);
     }

static int Compaq_VS_beep(int frequency, int length)
     {
	char buffer[VOICE_BUF_LEN];
	int true_length = length / voice_modem->beep_timeunit;
	int frequency2 = frequency / 2;
	
	reset_watchdog();
	
	if(frequency2 < 300)
	     frequency2 = frequency;
	
	sprintf(buffer, voice_modem->beep_cmnd, frequency / 2, frequency,
	 true_length);
	
	if (voice_command(buffer, "") != OK)
          return(FAIL);
	
	delay(((length - 1000) > 0) ? (length - 1000) : 0);
	
	if ((voice_command("", voice_modem->beep_answr) & VMA_USER) != VMA_USER)
          return(FAIL);
	
	return(OK);
     }
	
static int Compaq_VS_init(void)
     {
	char buffer[VOICE_BUF_LEN];
	
	reset_watchdog();
	voice_modem_state = INITIALIZING;
	lprintf(L_MESG, "initializing Compaq VS modem [Compaq_VS v0.01]");
	
	/* set silence detection threshold and duration */
	sprintf(buffer, "AT+VSD=%d,%d", cvd.rec_silence_threshold.d.i * 10 / 100 + 123, cvd.rec_silence_len.d.i);

	if(voice_command(buffer, "OK") != VMA_USER_1)
	     lprintf(L_WARN, "setting recording preferences didn't work");

	/* set receive gain in percent, normalize to 0 - 255 scale */

	if((cvd.receive_gain.d.i < 0) || (cvd.receive_gain.d.i > 100))
	     cvd.receive_gain.d.i = 75;
	
	sprintf(buffer, "AT+VGR=%d", cvd.receive_gain.d.i * 255 / 100);

	if(voice_command(buffer, "OK") != VMA_USER_1)
	     lprintf(L_WARN, "setting receive gain didn't work");
	
	/* set transmit gain in percent, normalize to 0 - 255 scale */

	if((cvd.transmit_gain.d.i < 0) || (cvd.transmit_gain.d.i > 100))
	     cvd.transmit_gain.d.i = 75;
	
	sprintf(buffer, "AT+VGT=%d", cvd.transmit_gain.d.i * 255 / 100);

	if(voice_command(buffer, "OK") != VMA_USER_1)
	     lprintf(L_WARN, "setting transmit gain didn't work");
	
	if(voice_command("AT+VLS=0", "OK") != VMA_USER_1)
	     lprintf(L_WARN, "can't deselect all input/output devices");

	voice_modem_state = IDLE;
	return(OK);
     }

/*
 * only support compression mode 4 for now, it's easy to support
 * valid modes for modem are:
 *   1  8bit linear at 7200,8000,11025 Hz
 *   2 16bit linear at 7200,8000,11025 Hz
 *   3  8bit alaw   at 8000 Hz
 *   4  8bit ulaw   at 8000 Hz
 */

static int Compaq_VS_set_compression (int *compression, int *speed, int *bits)
     {
	char buffer[VOICE_BUF_LEN];
	
	reset_watchdog();
	
	if(*compression == 0) 
	     *compression = 4;
	
	if(*speed == 0) 
	     *speed = 8000;
	
	if(*speed != 8000)
	     {
	     lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name,
	      *speed);
	     return(FAIL);
	     }
	
	if(*compression != 4)
	     {
	     lprintf(L_WARN, "%s: Illegal voice compression method (%d)",
	      voice_modem_name, *compression);
	     return(FAIL);
	     }

	*bits = 8;
	
	sprintf(buffer, "AT+VSM=%d", *compression + 127);
	
	if(voice_command(buffer, "OK") != VMA_USER_1)
	     return(FAIL);
	
	return(OK);
     }

static int Compaq_VS_set_device(int device)
     {
   	reset_watchdog();
	
	switch(device)
	     {
	     case NO_DEVICE:
	          voice_command("AT+VLS=0", "OK");
	          return(OK);
	     case DIALUP_LINE:
	          voice_command("AT+VLS=2", "OK");
	          return(OK);
	     case INTERNAL_SPEAKER:
	          voice_command("AT+VLS=4", "OK");
	          return(OK);
	     case INTERNAL_MICROPHONE:
	          voice_command("AT+VLS=6", "OK");
	          return(OK);
	     }
	
	lprintf(L_WARN, "%s: Unknown output device (%d)", voice_modem_name,
	 device);
	return(FAIL);
     }

const char Compaq_VS_pick_phone_cmnd[] = "AT+VLS=1";
const char Compaq_VS_pick_phone_answr[] = "OK|CONNECT";

voice_modem_struct Compaq_VS =
     {
	"Compaq VS Series Modem",
	"Compaq VS",
	(char *) Compaq_VS_pick_phone_cmnd,
	(char *) Compaq_VS_pick_phone_answr,
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
     // juergen.kosel@gmx.de : voice-duplex-patch start
	NULL,  /* (char *) V253modem_start_duplex_voice_cmnd, */
	NULL,  /* (char *) V253modemstart_duplex_voice_answr, */
	NULL,  /* (char *) V253modem_stop_duplex_voice_cmnd , */
	NULL,  /* (char *) V253modem_stop_duplex_voice_answr, */
     // juergen.kosel@gmx.de : voice-duplex-patch end
	&Compaq_VS_answer_phone,
	&Compaq_VS_beep,
	&IS_101_dial,
	&IS_101_handle_dle,
	&Compaq_VS_init,
	&IS_101_message_light_off,
	&IS_101_message_light_on,
	&IS_101_start_play_file,
	&IS_101_reset_play_file,
	&IS_101_stop_play_file,
	&IS_101_play_file,
	&IS_101_record_file,
	&Compaq_VS_set_compression,
	&Compaq_VS_set_device,
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
	&IS_101_handle_duplex_voice,
	NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
        0
     };
