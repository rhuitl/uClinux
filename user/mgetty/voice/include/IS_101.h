/*
 * voice_IS_101.h
 *
 * Defines the functions implemented in the generic IS 101 driver.
 *
 * $Id: IS_101.h,v 1.7 2005/03/13 17:27:42 gert Exp $
 *
 */

extern const char IS_101_pick_phone_cmnd[];
extern const char IS_101_pick_phone_answr[];
extern const char IS_101_beep_cmnd[];
extern const char IS_101_beep_answr[];
#define           IS_101_beep_timeunit 10
extern const char IS_101_hardflow_cmnd[];
extern const char IS_101_hardflow_answr[];
extern const char IS_101_softflow_cmnd[];
extern const char IS_101_softflow_answr[];
extern const char IS_101_start_play_cmnd[];
extern const char IS_101_start_play_answer[];
extern const char IS_101_reset_play_cmnd[];
extern const char IS_101_intr_play_cmnd[];
extern const char IS_101_intr_play_answr[];
extern const char IS_101_stop_play_cmnd[];
extern const char IS_101_stop_play_answr[];
extern const char IS_101_start_rec_cmnd[];
extern const char IS_101_start_rec_answr[];
extern const char IS_101_stop_rec_cmnd[];
extern const char IS_101_stop_rec_answr[];
extern const char IS_101_switch_mode_cmnd[];
extern const char IS_101_switch_mode_answr[];
extern const char IS_101_ask_mode_cmnd[];
extern const char IS_101_ask_mode_answr[];
extern const char IS_101_voice_mode_id[];
extern const char IS_101_play_dtmf_cmd[];
extern const char IS_101_play_dtmf_extra[];
extern const char IS_101_play_dtmf_answr[];


extern int IS_101_answer_phone (void);
extern int IS_101_beep (int frequency, int duration);
extern int IS_101_dial (char* number);
extern int IS_101_handle_dle (char code);
extern int IS_101_init (void);
extern int IS_101_message_light_off (void);
extern int IS_101_message_light_on (void);
extern int IS_101_start_play_file(void);
extern int IS_101_reset_play_file(void);
extern int IS_101_stop_play_file(void);
extern int IS_101_play_file (FILE *fd, int bps);
extern int IS_101_record_file (FILE *fd, int bps);
extern int IS_101_set_buffer_size (int size);
extern int IS_101_set_compression (int *compression, int *speed, int *bits);
extern int IS_101_set_device (int device);
extern int IS_101_stop_dialing (void);
extern int IS_101_stop_playing (void);
extern int IS_101_stop_recording (void);
extern int IS_101_stop_waiting (void);
extern int IS_101_switch_to_data_fax (char* mode);
extern int IS_101_voice_mode_off (void);
extern int IS_101_voice_mode_on (void);
extern int IS_101_wait (int timeout);
extern int IS_101_play_dtmf (char* number);
extern int IS_101_check_rmd_adequation(char *rmd_name);
// juergen.kosel@gmx.de : voice-duplex-patch start
extern int IS_101_handle_duplex_voice (FILE *tomodem, FILE *frommodem, int bps);
// juergen.kosel@gmx.de : voice-duplex-patch end


