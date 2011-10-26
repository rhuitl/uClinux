/*
 * no_modem.c
 *
 * This file contains a dummy event routine.
 *
 * $Id: no_modem.c,v 1.6 2005/03/13 17:27:44 gert Exp $
 *
 */

#include "../include/voice.h"

static int no_modem_answer_phone(void)
     {
     LPRINTF(L_WARN, "%s: answer_phone called", POS);
     return(FAIL);
     }

static int no_modem_beep(int frequency, int length)
     {
     LPRINTF(L_WARN, "%s: beep called", POS);
     return(FAIL);
     }

static int no_modem_dial(char *number)
     {
     LPRINTF(L_WARN, "%s: dial called", POS);
     return(FAIL);
     }

static int no_modem_handle_dle(char data)
     {
     LPRINTF(L_WARN, "%s: handle_dle called", POS);
     return(FAIL);
     }

static int no_modem_init(void)
     {
     LPRINTF(L_WARN, "%s: init called", POS);
     return(FAIL);
     }

static int no_modem_message_light_off(void)
     {
     LPRINTF(L_WARN, "%s: message_light_off called", POS);
     return(FAIL);
     }

static int no_modem_message_light_on(void)
     {
     LPRINTF(L_WARN, "%s: message_light_on called", POS);
     return(FAIL);
     }

static int no_modem_start_play_file(void)
     {
     LPRINTF(L_WARN, "%s: start_play_file called", POS);
     return(FAIL);
     }

static int no_modem_reset_play_file(void)
     {
     LPRINTF(L_WARN, "%s: next_play_file called", POS);
     return(FAIL);
     }

static int no_modem_stop_play_file(void)
     {
     LPRINTF(L_WARN, "%s: stop_play_file called", POS);
     return(FAIL);
     }

static int no_modem_play_file(FILE *fd, int bps)
     {
     LPRINTF(L_WARN, "%s: play_file called", POS);
     return(FAIL);
     }

static int no_modem_record_file(FILE *fd, int bps)
     {
     LPRINTF(L_WARN, "%s: record_file called", POS);
     return(FAIL);
     }

static int no_modem_set_compression(int *compression, int *speed, int *bits)
     {
     LPRINTF(L_WARN, "%s: set_compression called", POS);
     return(FAIL);
     }

static int no_modem_set_device(int device)
     {
     LPRINTF(L_WARN, "%s: set_device called", POS);
     return(FAIL);
     }

static int no_modem_stop_dialing(void)
     {
     LPRINTF(L_WARN, "%s: stop_dialing called", POS);
     return(FAIL);
     }

static int no_modem_stop_playing(void)
     {
     LPRINTF(L_WARN, "%s: stop_playing called", POS);
     return(FAIL);
     }

static int no_modem_stop_recording(void)
     {
     LPRINTF(L_WARN, "%s: stop_recording called", POS);
     return(FAIL);
     }

static int no_modem_stop_waiting(void)
     {
     LPRINTF(L_WARN, "%s: stop_waiting called", POS);
     return(FAIL);
     }

static int no_modem_switch_to_data_fax(char *mode)
     {
     LPRINTF(L_WARN, "%s: switch_to_data_fax called", POS);
     return(FAIL);
     }

static int no_modem_voice_mode_off(void)
     {
     LPRINTF(L_WARN, "%s: voice_mode_off called", POS);
     return(FAIL);
     }

static int no_modem_voice_mode_on(void)
     {
     LPRINTF(L_WARN, "%s: voice_mode_on called", POS);
     return(FAIL);
     }

static int no_modem_wait(int wait_timeout)
     {
     LPRINTF(L_WARN, "%s: wait called", POS);
     return(FAIL);
     }

static int no_modem_play_dtmf(char* number)
     {
     LPRINTF(L_WARN, "%s: play_dtmf called", POS);
     return(FAIL);
     }

voice_modem_struct no_modem =
     {
     "serial port",
     "none",
     "",
     "",
     "",
     "",
     0,
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",
     "",

     &no_modem_answer_phone,
     &no_modem_beep,
     &no_modem_dial,
     &no_modem_handle_dle,
     &no_modem_init,
     &no_modem_message_light_off,
     &no_modem_message_light_on,
     &no_modem_start_play_file,
     &no_modem_reset_play_file,
     &no_modem_stop_play_file,
     &no_modem_play_file,
     &no_modem_record_file,
     &no_modem_set_compression,
     &no_modem_set_device,
     &no_modem_stop_dialing,
     &no_modem_stop_playing,
     &no_modem_stop_recording,
     &no_modem_stop_waiting,
     &no_modem_switch_to_data_fax,
     &no_modem_voice_mode_off,
     &no_modem_voice_mode_on,
     &no_modem_wait,
     &no_modem_play_dtmf
     };
