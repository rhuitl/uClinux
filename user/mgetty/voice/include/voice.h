/*
 * voice.h
 *
 * This is the main header file for vgetty, vm and the pvf tools.
 * It includes other header files and defines some global variables.
 *
 * $Id: voice.h,v 1.14 2005/03/13 17:27:42 gert Exp $
 *
 */

#ifndef VOICE_INCLUDE_VOICE_H
#define VOICE_INCLUDE_VOICE_H

#ifndef _NOSTDLIB_H
# include <stdlib.h>
#endif

#include <stdio.h>
#include <unistd.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>

#if !defined( __bsdi__ ) && !defined(__FreeBSD__) && !defined(NeXT) && !defined(__OpenBSD__)
# include <malloc.h>
#endif

#include <math.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>

#ifndef VOICE
# include "../../mgetty.h"
# include "../../config.h"
# include "../../policy.h"
# include "../../tio.h"
# include "../../fax_lib.h"
#endif

#include "IS_101.h"
#include "bitsizes.h"
#include "util.h"
#include "config.h"
#include "event.h"
#include "hardware.h"
#include "header.h"
#include "paths.h"
#include "pvf.h"

/*
 * Debugging info
 */

extern char POS[80];
#define LPRINTF sprintf(POS, "%s%s%03d%s%s%s", \
 __FILE__, " [", __LINE__, "] ", __FUNCTION__, ":"); lprintf

/*
 * Buffer length for commands, voice modem answers and so on
 */

#define VOICE_BUF_LEN (256)

/*
 * Program and release information
 */

extern char *vgetty_version;
extern char *program_name;

/*
 * Global variables
 */

extern int voice_fd;
extern int voice_shell_state;
extern int voice_shell_signal;
extern int voice_shell_linger;
extern char voice_config_file[VOICE_BUF_LEN];
extern char *DevID;
extern TIO tio_save;
extern TIO voice_tio;

/*
 * Vgetty global variables
 */

extern boolean virtual_ring;
extern int answer_mode;
extern char dtmf_code[VOICE_BUF_LEN];
extern int execute_dtmf_script;
extern int first_dtmf;
extern int hangup_requested;
extern int switch_to_data_fax_mode;

/*
 * mgetty functions
 */

#ifndef VOICE
extern void get_ugid(char* user, char* group, uid_t* uid, gid_t* gid);
#endif

/*
 * The voice library functions
 */

extern int voice_analyze(char *buffer, char *expected_answers,
 int exact_match);
#define voice_answer_phone() voice_modem->answer_phone()
#define voice_beep(a,b) voice_modem->beep(a,b)
extern int voice_check_for_input(void);
extern int voice_close_device(void);
extern int voice_command(char *command, char *expected_answers);
extern int voice_config(char *new_program_name, char *DevID);
extern int voice_detect_modemtype(void);
extern int voice_impersonify(void);
extern int voice_desimpersonify(void);
#define voice_dial(a) voice_modem->dial(a)
extern int voice_execute_shell_script(char *shell_script,
 char **shell_options);
extern void voice_flush(int timeout);
#define voice_handle_dle(a) voice_modem->handle_dle(a)
extern int voice_handle_event(int event, event_data data);
extern int voice_init(void);
#define voice_message_light_off() voice_modem->message_light_off()
#define voice_message_light_on() voice_modem->message_light_on()
extern int voice_mode_on(void);
extern int voice_mode_off(void);
extern int voice_open_device(void);
extern int voice_play_file(char *name);
extern int voice_read(char *buffer);
extern int voice_read_byte(void);
extern int voice_read_char(void);
extern int voice_read_shell(char *buffer);
extern int voice_register_event_handler(int (*new_program_handle_event)
 (int event, event_data data));
extern int voice_record_file(char *name);
extern int voice_shell_handle_event(int event, event_data data);
#define voice_set_device(a) voice_modem->set_device(a)
extern int voice_stop_current_action(void);
#define voice_stop_dialing() voice_modem->stop_dialing()
#define voice_stop_playing() voice_modem->stop_playing()
#define voice_stop_recording() voice_modem->stop_recording()
#define voice_stop_waiting() voice_modem->stop_waiting()
// juergen.kosel@gmx.de : voice-duplex-patch start
#define voice_stop_duplex() voice_modem->stop_duplex_voice()
// juergen.kosel@gmx.de : voice-duplex-patch end
extern char *voice_strsep(char **stringp, const char *delim);
#define voice_switch_to_data_fax(a) voice_modem->switch_to_data_fax(a)
extern int voice_unregister_event_handler(void);
#define voice_wait(a) voice_modem->wait(a)
extern void reset_watchdog(void);
extern int voice_faxsnd(char **name, int switchbd, int max_tries);
extern void voice_faxrec(char * spool_in, unsigned int switchbd);
extern int enter_data_fax_mode(int mode);
#define voice_play_dtmf(a) voice_modem->play_dtmf(a)
#define voice_modem_quirks() (voice_modem->voice_modem_quirks)

#ifdef USE_VARARGS
extern int voice_write();
#else
extern int voice_write(const char *format, ...);
#endif

extern int voice_write_char(char charout);
extern int voice_write_raw(char *buffer, int count);

#ifdef USE_VARARGS
extern int voice_write_shell();
#else
extern int voice_write_shell(const char *format, ...);
#endif

/*
 * Internal functions
 */

extern void voice_check_events(void);

/*
 * The vgetty functions
 */

extern int vgetty_answer(int rings, int rings_wanted, int dist_ring);
extern void vgetty_button(int rings);
extern void vgetty_create_message_flag_file(void);
extern int vgetty_handle_event(int event, event_data data);
extern void vgetty_message_light(void);
extern void vgetty_rings(int *rings_wanted);

/*
 * Value for voice_fd if the port isn't open
 */

#define NO_VOICE_FD (-1)

/*
 * Possible input or output devices. For details look in
 * contrib/Steffen_Klupsch-new-set-device-modes
 */

#define NO_DEVICE           (0x0001)
#define DIALUP_LINE         (0x0002)
#define EXTERNAL_MICROPHONE (0x0003)
#define INTERNAL_MICROPHONE (0x0004)
#define EXTERNAL_SPEAKER    (0x0005)
#define INTERNAL_SPEAKER    (0x0006)
#define LOCAL_HANDSET       (0x0007)

#define DIALUP_WITH_EXT_SPEAKER              (0x0008)
#define DIALUP_WITH_INT_SPEAKER              (0x0009)
#define DIALUP_WITH_LOCAL_HANDSET            (0x000A)
#define DIALUP_WITH_EXTERNAL_MIC_AND_SPEAKER (0x000B)
#define DIALUP_WITH_INTERNAL_MIC_AND_SPEAKER (0x000C)

#define NUMBER_OF_MODEM_DEVICE_MODES (0x000C)

extern char *voice_device_mode_name(int i);

/*
 * Voice modem answers
 */

/*
 * The user defined ones
 */

#define VMA_USER         (0x1000)
#define VMA_USER_1       (0x1000)
#define VMA_USER_2       (0x1001)
#define VMA_USER_3       (0x1002)
#define VMA_USER_4       (0x1003)
#define VMA_USER_5       (0x1004)
#define VMA_USER_6       (0x1005)
#define VMA_USER_7       (0x1006)
#define VMA_USER_8       (0x1007)
#define VMA_USER_9       (0x1008)
#define VMA_USER_10      (0x1009)
#define VMA_USER_11      (0x100a)
#define VMA_USER_12      (0x100b)
#define VMA_USER_13      (0x100c)
#define VMA_USER_14      (0x100d)
#define VMA_USER_15      (0x100e)
#define VMA_USER_16      (0x100f)

/*
 * The default ones
 */

#define VMA_DEFAULT      (0x2000)
#define VMA_BUSY         (0x2000)
#define VMA_CONNECT      (0x2001)
#define VMA_EMPTY        (0x2002)
#define VMA_ERROR        (0x2003)
#define VMA_FAX          (0x2004)
#define VMA_FCON         (0x2005)
#define VMA_FCO          (0x2006)
#define VMA_NO_ANSWER    (0x2007)
#define VMA_NO_CARRIER   (0x2008)
#define VMA_NO_DIAL_TONE (0x2009)
#define VMA_OK           (0x200a)
#define VMA_RINGING      (0x200b)
#define VMA_RING_1       (0x200c)
#define VMA_RING_2       (0x200d)
#define VMA_RING_3       (0x200e)
#define VMA_RING_4       (0x200f)
#define VMA_RING_5       (0x2010)
#define VMA_RING         (0x2011)
#define VMA_VCON         (0x2012)

/*
 * additonal events (from V.253)
 */
#define VMA_DLE_SHIELD   (0x2013)
#define VMA_DATE         (0x2014)
#define VMA_TIME         (0x2015)
#define VMA_NMBR         (0x2016)
#define VMA_MESG         (0x2017)
#define VMA_ERRM         (0x2018)
#define VMA_DRON         (0x2019)
#define VMA_DROF         (0x201a)
#define VMA_CPON         (0x201b)
#define VMA_CPOF         (0x201c)
#define VMA_CWON         (0x201d)
#define VMA_CWOF         (0x201e)

/*
 * For the unsupported manufacturer specific events.
 * At least they shouldn't break anything
 */
#define VMA_IGNORED      (0x2100)

/*
 * If something goes wrong
 */

#define VMA_FAIL         (0x4000)

/* Something goes wrong, but there is no need to stop
 * example:
 *     The actual device is DIALUP_LINE
 *     Then DIALUP_WITH_EXT_SPEAKER is selected
 *     the modem has no EXT_SPEAKER and stays on
 *     DIALUP_LINE
 *     Now the calling function could decide to
 *     1. Terminate
 *     2. Go on with only DIALUP_LINE
 *     3. Try DIALUP_WITH_INT_SPEAKER
 */
#define VMA_DEVICE_NOT_AVAIL (0x4001) 


/*
 * Possible voice modem and shell execution states
 */

#define DIALING          (0x0000)
#define IDLE             (0x0001)
#define INITIALIZING     (0x0002)
#define OFF_LINE         (0x0003)
#define ON_LINE          (0x0004)
#define PLAYING          (0x0005)
#define RECORDING        (0x0006)
#define WAITING          (0x0007)
// juergen.kosel@gmx.de : voice-duplex-patch start
#define DUPLEXMODE       (0x0008)
// juergen.kosel@gmx.de : voice-duplex-patch end

/*
 * The different vgetty answer modes
 */

#define ANSWER_DATA  (1)
#define ANSWER_FAX   (2)
#define ANSWER_VOICE (4)

/*
 * Some tricks for vgetty
 */

#ifdef VOICE
# undef LOG_PATH
# define LOG_PATH VGETTY_LOG_PATH
#endif

#endif /* VOICE_INCLUDE_VOICE_H */
