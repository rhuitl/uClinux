/* $Id: V253ugly.c,v 1.1 2005/03/13 18:15:40 gert Exp $
 *
 * V253ugly.c - workaround modem "type" for V.253 modems that can't do AT+IFC
 *
 * $Log: V253ugly.c,v $
 * Revision 1.1  2005/03/13 18:15:40  gert
 * Some V.253 modems refuse AT+IFC=... to set flow control -> this modem
 * "driver" works around it by cloning all of V.253 except flow control
 *
 */

#include "../include/V253modem.h"


const char V253ugly_hardflow_cmnd[] = "AT";
const char V253ugly_softflow_cmnd[] = "AT";

voice_modem_struct V253ugly = 
    {
    "V253 ugly",
    V253modem_RMD_NAME,
     (char *) V253modem_pick_phone_cmnd,
     (char *) V253modem_pick_phone_answr,
     (char *) V253modem_beep_cmnd,
     (char *) IS_101_beep_answr,
              IS_101_beep_timeunit,
     (char *) V253ugly_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) V253ugly_softflow_cmnd,
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
     (char *) V253modem_start_duplex_voice_cmnd,
     (char *) V253modemstart_duplex_voice_answr,
     (char *) V253modem_stop_duplex_voice_cmnd ,
     (char *) V253modem_stop_duplex_voice_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch end

    &IS_101_answer_phone,
    &IS_101_beep,
    &IS_101_dial,
    &IS_101_handle_dle,
    &V253modem_init,
    &IS_101_message_light_off,
    &IS_101_message_light_on,
    &IS_101_start_play_file,
    NULL,
    &IS_101_stop_play_file,
    &IS_101_play_file,
    &IS_101_record_file,
    &V253modem_set_compression,
    &V253modem_set_device,
    &IS_101_stop_dialing,
    &IS_101_stop_playing,
    &IS_101_stop_recording,
    &IS_101_stop_waiting,
    &IS_101_switch_to_data_fax,
    &IS_101_voice_mode_off,
    &IS_101_voice_mode_on,      /* it's also possible to say AT+FCLASS=8.0 */
    &IS_101_wait,
    &IS_101_play_dtmf,
    &V253_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
    &V253modem_handle_duplex_voice,
    &V253modem_stop_duplex,
     // juergen.kosel@gmx.de : voice-duplex-patch end
    0
    };

