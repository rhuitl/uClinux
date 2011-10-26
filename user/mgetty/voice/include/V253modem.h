#ifndef VOICE_INCLUDE_V253_H_
#define VOICE_INCLUDE_V253_H_
/*
 * Defines the functions implemented in voice/libvoice/V253modem.c
 * I wrote this with the hope that vm scripts written for a none full V253 compatible modem
 * should also run on full V253 compatible modems.
 */
#include "../include/voice.h"

#define V253modem_RMD_NAME "V253modem"
#define ELSA_RMD_NAME "Elsa"

int V253modem_set_device (int device);
int V253modem_init (void);
int V253modem_set_compression (int *compression, int *speed, int *bits);
int V253modem_set_device (int device);
int V253_check_rmd_adequation(char *rmd_name);
// juergen.kosel@gmx.de : voice-duplex-patch start
int V253modem_handle_duplex_voice(FILE *tomodem, FILE *frommodem, int bps);
int V253modem_stop_duplex (void);
// juergen.kosel@gmx.de : voice-duplex-patch end
void V253_init_compression_table();
void V253_querry_compressions();

/* AT-command strings and answers */
extern const char V253modem_pick_phone_cmnd[];
extern const char V253modem_pick_phone_answr[];
extern const char V253modem_hardflow_cmnd[];
extern const char V253modem_softflow_cmnd[];
extern const char V253modem_beep_cmnd[];
// juergen.kosel@gmx.de : voice-duplex-patch start
extern const char V253modem_start_duplex_voice_cmnd [];
extern const char V253modemstart_duplex_voice_answr [];
extern const char V253modem_stop_duplex_voice_cmnd [] ;
extern const char V253modem_stop_duplex_voice_answr [];
// juergen.kosel@gmx.de : voice-duplex-patch end



#endif
