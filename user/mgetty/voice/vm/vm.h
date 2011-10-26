/* vm.h
 *
 * This file contains definitions for global variables and functions
 * for the VoiceModem program.
 *
 * $Id: vm.h,v 1.4 1998/09/09 21:08:13 gert Exp $
 *
 */

#include "../include/voice.h"

/*
 * DTMF code handling defines
 */

#define IGNORE_DTMF      (0)
#define READ_DTMF_DIGIT  (1)
#define READ_DTMF_STRING (2)

/*
 * Global variables prototypes
 */

extern int dtmf_mode;
extern char dtmf_string_buffer[VOICE_BUF_LEN];
extern int use_on_hook_off_hook;
extern int start_action;

/*
 * Function prototypes
 */

extern int handle_event(int event, event_data data);
extern void usage();
