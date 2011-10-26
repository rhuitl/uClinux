/*
 * Multitech_5600ZDXv.c
 *
 * This file contains the DYNALINK V1414VQE specific hardware stuff.
 *
 * This file is originally written for the Elsa 28.8 modem by:
 * Stefan Froehlich <Stefan.Froehlich@tuwien.ac.at>.
 *
 * Since commands are the same I've copied the code, and left out some
 * Elsa features....
 * The rockwell/dynalink V1414VQE is now maintained by:
 * Ard van Breemen <ard@cstmel.hobby.nl>.
 *
 * Removed most stuff from this file, since the new IS-101 driver can be
 * used now. (Marc 04.01.1997)
 *
 * This file then adapted for the Multitec MT5600ZDXv by
 * Bill Nugent <whn@lopi.com>
 *
 * $Id: Multitech_5600ZDXv.c,v 1.5 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static int
Multitech_5600ZDXv_handle_dle(char data)
{
  switch (data) {
    /*
     * Local handset goes off hook
     */

    case 't':
      return(queue_event(create_event(HANDSET_OFF_HOOK)));

  }

  return(IS_101_handle_dle(data));
}

static int
Multitech_5600ZDXv_init(void)
{
  char buffer[VOICE_BUF_LEN];

  reset_watchdog();
  lprintf(L_MESG, "initializing Multitech MT5600ZDXv voice modem");
  voice_modem_state = INITIALIZING;
  sprintf(buffer, "AT#VSP=%1u", cvd.rec_silence_len.d.i);

  if (voice_command(buffer, "OK") != VMA_USER_1)
    lprintf(L_WARN, "can't set silence period");

  if (voice_command("AT#VSD=0", "OK") != VMA_USER_1)
    lprintf(L_WARN, "can't disable silence deletion");

  if (voice_command("AT#VTD=3F,3F,3F", "OK") != VMA_USER_1)
    lprintf(L_WARN, "can't set DLE responses");

  if ((cvd.rec_silence_threshold.d.i > 100) ||
      (cvd.rec_silence_threshold.d.i < 0)) {
    lprintf(L_WARN, "Invalid threshold value.");
    return(ERROR);
  }

  sprintf(buffer, "AT#VSS=%1u", cvd.rec_silence_threshold.d.i * 3 / 100);

  if (voice_command(buffer, "OK") != VMA_USER_1)
    lprintf(L_WARN, "can't set silence threshold");

  if (voice_command("AT&K3", "OK") == VMA_USER_1) {
    TIO tio;

    tio_get(voice_fd, &tio);
    tio_set_flow_control(voice_fd, &tio, FLOW_HARD);
    tio_set(voice_fd, &tio);
  } else {
    lprintf(L_WARN, "can't turn on hardware flow control");
  }
  voice_modem_state = IDLE;
  return(OK);
}

static int
Multitech_5600ZDXv_set_compression (int *compression, int *speed, int *bits)
{
  char buf[VOICE_BUF_LEN];

  reset_watchdog();
  /*
   * Build the speed command and send it
   */
  switch (*speed) {
    case 0:
      *speed = 7200;
      /* FALL THROUGH */
    case 7200:
    case 11025:
      break;

    default:
      lprintf(L_WARN, "%s: Illegal sample rate (%d)", voice_modem_name, *speed);
      return(FAIL);
  }
  if (sprintf(buf, "AT#VSR=%d", *speed) == -1) {
    lprintf(L_ERROR, "%s: Command too long", __FUNCTION__);
  }
  if (voice_command(buf, "OK") != VMA_USER_1) {
    return(FAIL);
  }
  /*
   * Build the number of bits and send it
   */
  switch (*compression) {
    case 0:
      *compression = 2;
      /* FALL THROUGH */
    case 2:
    case 4:
    case 8:
      *bits = *compression;
      break;

    default:
      lprintf(L_WARN,
              "ROCKWELL handle event: Illegal voice compression method (%d)",
              *compression);
      return(FAIL);
  }
  if (sprintf(buf, "AT#VBS=%d", *bits) == -1) {
    lprintf(L_ERROR, "%s: Command too long", __FUNCTION__);
  }
  if (voice_command(buf, "OK") != VMA_USER_1) {
    return(FAIL);
  }
  return (OK);
}

static int
Multitech_5600ZDXv_set_device (int device)
{
  static int current_device = -1;

  reset_watchdog();

  if ((current_device != device) && (current_device >= 0)) {
    voice_command("ATH0","VCON|OK");
  }

  current_device=device;

  switch (device) {
    case NO_DEVICE:
      voice_command("AT#VLS=0", "OK");
      break;
    case DIALUP_LINE:
      voice_command("AT#VLS=4", "OK");
      break;
    case EXTERNAL_MICROPHONE:
      voice_command("AT#VLS=3", "VCON");
      break;
    case INTERNAL_SPEAKER:
      voice_command("AT#VLS=2", "VCON");
      break;
    case LOCAL_HANDSET:
      voice_command("AT#VLS=1","VCON");
      break;
    default:
      lprintf(L_WARN, "%s: Unknown output device (%d)",
              voice_modem_name, device);
      return(FAIL);
  }
  return(OK);
}

static char Multitech_5600ZDXv_pick_phone_cmnd[] = "ATA";
static char Multitech_5600ZDXv_pick_phone_answr[] = "VCON";
static char Multitech_5600ZDXv_beep_cmnd[] = "AT#VTS=[%d,0,%d]";
#define     Multitech_5600ZDXv_beep_timeunit 100
static char Multitech_5600ZDXv_hardflow_cmnd[] = "AT&K3";
static char Multitech_5600ZDXv_softflow_cmnd[] = "AT&K4";
static char Multitech_5600ZDXv_start_play_cmnd[] = "AT#VTX";
static char Multitech_5600ZDXv_intr_play_answr[] = "OK|VCON";
static char Multitech_5600ZDXv_stop_play_answr[] = "OK|VCON";
static char Multitech_5600ZDXv_start_rec_cmnd[] = "AT#VRX";
static char Multitech_5600ZDXv_stop_rec_cmnd[] = {'!', 0x00};
static char Multitech_5600ZDXv_stop_rec_answr[] = "OK|VCON";
static char Multitech_5600ZDXv_switch_mode_cmnd[] = "AT#CLS=";
static char Multitech_5600ZDXv_ask_mode_cmnd[] = "AT#CLS?";

voice_modem_struct Multitech_5600ZDXv =
     {
     "Multitech_5600ZDXv",
     "Rockwell",
     (char *) Multitech_5600ZDXv_pick_phone_cmnd,
     (char *) Multitech_5600ZDXv_pick_phone_answr,
     (char *) Multitech_5600ZDXv_beep_cmnd,
     (char *) IS_101_beep_answr,
              Multitech_5600ZDXv_beep_timeunit,
     (char *) Multitech_5600ZDXv_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) Multitech_5600ZDXv_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) Multitech_5600ZDXv_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) IS_101_intr_play_cmnd,
     (char *) Multitech_5600ZDXv_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) Multitech_5600ZDXv_stop_play_answr,
     (char *) Multitech_5600ZDXv_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) Multitech_5600ZDXv_stop_rec_cmnd,
     (char *) Multitech_5600ZDXv_stop_rec_answr,
     (char *) Multitech_5600ZDXv_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) Multitech_5600ZDXv_ask_mode_cmnd,
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
     &IS_101_beep,
     &IS_101_dial,
     &Multitech_5600ZDXv_handle_dle,
     &Multitech_5600ZDXv_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     NULL,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &Multitech_5600ZDXv_set_compression,
     &Multitech_5600ZDXv_set_device,
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



