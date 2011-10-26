/*
 * voice_event.h
 *
 * Defines the event_data structure for information exchange between
 * the hardware specific parts and the generic code.
 *
 * $Id: event.h,v 1.4 1998/09/09 21:06:34 gert Exp $
 *
 */

/*
 * Dummy empty event.
 */

#define NO_EVENT                 (0x0000)

/*
 * Possible event messages for the voice modem
 */

#define VOICE_CODE_EVENT         (0x1000)
#define VOICE_ANSWER_PHONE       (0x1000)
#define VOICE_BEEP               (0x1001)
#define VOICE_DIAL               (0x1002)
#define VOICE_HANDLE_DLE         (0x1003)
#define VOICE_INIT               (0x1004)
#define VOICE_MESSAGE_LIGHT_ON   (0x1005)
#define VOICE_MESSAGE_LIGHT_OFF  (0x1006)
#define VOICE_MODE_OFF           (0x1007)
#define VOICE_MODE_ON            (0x1008)
#define VOICE_PLAY_FILE          (0x1009)
#define VOICE_RECORD_FILE        (0x100a)
#define VOICE_SET_COMPRESSION    (0x100b)
#define VOICE_SET_DEVICE         (0x100c)
#define VOICE_STOP_DIALING       (0x100d)
#define VOICE_STOP_PLAYING       (0x100e)
#define VOICE_STOP_RECORDING     (0x100f)
#define VOICE_STOP_WAITING       (0x1010)
#define VOICE_SWITCH_TO_DATA_FAX (0x1011)
#define VOICE_WAIT               (0x1012)

/*
 * Possible event messages from the voice modem
 */

#define VOICE_MODEM_EVENT        (0x2000)
#define BONG_TONE                (0x2000)
#define BUSY_TONE                (0x2001)
#define CALL_WAITING             (0x2002)
#define DIAL_TONE                (0x2003)
#define DATA_CALLING_TONE        (0x2004)
#define DATA_OR_FAX_DETECTED     (0x2005)
#define FAX_CALLING_TONE         (0x2006)
#define HANDSET_ON_HOOK          (0x2007)
#define HANDSET_OFF_HOOK         (0x2008)
#define LOOP_BREAK               (0x2009)
#define LOOP_POLARITY_CHANGE     (0x200a)
#define NO_ANSWER                (0x200b)
#define NO_CARRIER               (0x200c)
#define NO_DIAL_TONE             (0x200d)
#define NO_VOICE_ENERGY          (0x200e)
#define RING_DETECTED            (0x200f)
#define RINGBACK_DETECTED        (0x2010)
#define RECEIVED_DTMF            (0x2011)
#define SILENCE_DETECTED         (0x2012)
#define SIT_TONE                 (0x2013)
#define TDD_DETECTED             (0x2014)
#define VOICE_DETECTED           (0x2015)

/*
 * Possible signal events
 */

#define SIGNAL_EVENT             (0x4000)
#define RESET_WATCHDOG           (0x4000)
#define SIGNAL_SIGCHLD           (0x4001)
#define SIGNAL_SIGHUP            (0x4002)
#define SIGNAL_SIGINT            (0x4003)
#define SIGNAL_SIGPIPE           (0x4004)
#define SIGNAL_SIGQUIT           (0x4005)
#define SIGNAL_SIGTERM           (0x4006)
#define SIGNAL_SIGUSR1           (0x4007)
#define SIGNAL_SIGUSR2           (0x4008)

/*
 * Event data structures
 */

typedef union
     {
     char c;
     int i;
     void *p;

     struct
          {
          int frequency;
          int length;
          } beep;

     } event_data;

typedef struct
     {
     int event;
     event_data data;
     } event_type;

/*
 * Event handling functions
 */

extern event_type* create_event(int event);
extern void clear_event(event_type* event);
extern int queue_event(event_type* event);
extern event_type* unqueue_event(void);
extern int voice_install_signal_handler(void);
extern int voice_restore_signal_handler(void);
