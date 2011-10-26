/*
 * Multitech_5634ZPX.c
 *
 * Hacked by <Harlan.Stenn@pfcs.com>. Maybe will be merged
 * with the other Multitech driver.
 *
 * $Id: Multitech_5634ZPX.c,v 1.3 2005/03/13 17:27:46 gert Exp $
 *
 * Some functions can't be static because inherited by Multitech_5634ZPX_ISA.
 * Copied by md 2000/12/14
 */

#include "../include/voice.h"

static char mode_save[16] = "";

int Multitech_5634ZPX_answer_phone(void)
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

int Multitech_5634ZPX_init(void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing %s voice modem", voice_modem->name);

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
      * AT+VSD=x,y - Set silence threshold and duration. 0-256, .1sec
      */

     sprintf(buffer, "AT+VSD=%d,%d", /*cvd.rec_silence_threshold.d.i *
      1 / 100 +*/ 128, cvd.rec_silence_len.d.i);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting recording preferences didn't work");

     /*
      * AT+VGT - Set the transmit gain for voice samples.  (128 is 1.0)
      */

     if (cvd.transmit_gain.d.i == -1)
          cvd.transmit_gain.d.i = 50;

     sprintf(buffer, "AT+VGT=%d", cvd.transmit_gain.d.i * 144 / 100 +
      56);

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting transmit gain didn't work");

     /*
      * AT+VGR - Set receive gain for voice samples.  (128 is 1.0)
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

int Multitech_5634ZPX_set_compression(int *compression, int *speed,
 int *bits)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();

     if (*compression == 0)
          *compression = 132;

     if (*speed == 0)
          *speed = 8000;

     if (*speed != 8000)
          {
          lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name,
           *speed);
          return(FAIL);
          }

     /*
        VSM=cml,vsr,scs,sel
	cml: 128-256 (compression method)
		128,"8-BIT LINEAR",(7200,8000,11025)
		129,"16-BIT LINEAR",(7200,8000,11025)
		130,"8-BIT ALAW",(8000)
		131,"8-BIT ULAW",(8000)
		132,"IMA ADPCM",(7200,8000,11025)
	vsr: (voice sample rate)
	scs: 0 (disabled), 1-n (how much noise is silence)
	sel: 0 (disabled), 1-n (.1 sec incr: silence expansion)
     */
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

static int Multitech_5634ZPX_set_device(int device)
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
               voice_command("AT+VLS=0", "OK"); /* MD: Changed from 1 to 0 -> now vm dials out */
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

void Multitech_5634ZPX_fix_modem(int expect_error)
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
        	lprintf(L_WARN, "%s: Modem answered correctly", program_name);
        if (result != VMA_USER_1 && !expect_error)
        	lprintf(L_WARN, "%s: Modem answered incorrectly", program_name); 
}

int Multitech_5634ZPX_switch_to_data_fax(char *mode)
{
	char buffer[VOICE_BUF_LEN];

	sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd, mode);

	if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
	    VMA_USER)
		return FAIL;

	Multitech_5634ZPX_fix_modem(1);

	return OK;
}

int Multitech_5634ZPX_voice_mode_off(void)
{
	char buffer[VOICE_BUF_LEN];

	sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd, mode_save);

	if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
	    VMA_USER)
		return FAIL;

	Multitech_5634ZPX_fix_modem(1);

	return OK;
}

int Multitech_5634ZPX_voice_mode_on(void)
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

	Multitech_5634ZPX_fix_modem(0);

	return OK;
}

#define Multitech_beep_timeunit	100

voice_modem_struct Multitech_5634ZPX =
     {
     "Multitech 5634ZPX",
     "Multitech5634",
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
     &Multitech_5634ZPX_set_device,
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





