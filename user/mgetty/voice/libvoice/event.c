/*
 * event.c
 *
 * This is the callback function for the modem to the higher level
 * routines.
 *
 * $Id: event.c,v 1.9 2005/03/13 17:27:46 gert Exp $
 *
 */

#include "../include/voice.h"

static volatile int event_count = 0;
static volatile int first_event = 0;
static volatile int last_event = 0;
int (*program_handle_event) (int event, event_data data) = NULL;

#define MAX_EVENTS 64

static volatile struct
     {
     int write_lock;
     int read_lock;
     event_type* event;
     } event_queue[MAX_EVENTS];

static struct
     {
     char *name;
     int number;
     } event_names[] =
     {
     {"BONG_TONE",                BONG_TONE},
     {"BUSY_TONE",                BUSY_TONE},
     {"CALL_WAITING",             CALL_WAITING},
     {"DIAL_TONE",                DIAL_TONE},
     {"DATA_CALLING_TONE",        DATA_CALLING_TONE},
     {"DATA_OR_FAX_DETECTED",     DATA_OR_FAX_DETECTED},
     {"FAX_CALLING_TONE",         FAX_CALLING_TONE},
     {"HANDSET_ON_HOOK",          HANDSET_ON_HOOK},
     {"HANDSET_OFF_HOOK",         HANDSET_OFF_HOOK},
     {"LOOP_BREAK",               LOOP_BREAK},
     {"LOOP_POLARITY_CHANGE",     LOOP_POLARITY_CHANGE},
     {"NO_ANSWER",                NO_ANSWER},
     {"NO_CARRIER",               NO_CARRIER},
     {"NO_DIAL_TONE",             NO_DIAL_TONE},
     {"NO_VOICE_ENERGY",          NO_VOICE_ENERGY},
     {"RING_DETECTED",            RING_DETECTED},
     {"RINGBACK_DETECTED",        RINGBACK_DETECTED},
     {"RECEIVED_DTMF",            RECEIVED_DTMF},
     {"SILENCE_DETECTED",         SILENCE_DETECTED},
     {"SIT_TONE",                 SIT_TONE},
     {"TDD_DETECTED",             TDD_DETECTED},
     {"VOICE_DETECTED",           VOICE_DETECTED},
     {"RESET_WATCHDOG",           RESET_WATCHDOG},
     {"SIGNAL_SIGCHLD",           SIGNAL_SIGCHLD},
     {"SIGNAL_SIGHUP",            SIGNAL_SIGHUP},
     {"SIGNAL_SIGINT",            SIGNAL_SIGINT},
     {"SIGNAL_SIGPIPE",           SIGNAL_SIGPIPE},
     {"SIGNAL_SIGQUIT",           SIGNAL_SIGQUIT},
     {"SIGNAL_SIGTERM",           SIGNAL_SIGTERM},
     {"SIGNAL_SIGUSR1",           SIGNAL_SIGUSR1},
     {"SIGNAL_SIGUSR2",           SIGNAL_SIGUSR2},
     {"", 0}
     };

char *event_name(int event)
     {
     static int i = 0;
     static char tmp_string[10];

     for (i = 0; (event_names[i].number != 0); i++)

          if (event_names[i].number == event)
               return(event_names[i].name);

     sprintf(tmp_string, "0x%04x", event);
     return(tmp_string);
     }

void reset_watchdog(void)
     {
     queue_event(create_event(RESET_WATCHDOG));
     }

int voice_handle_event(int event, event_data data)
     {
     int result;
     char buffer[2];

     buffer[0] = data.c;
     buffer[1] = '\0';
     lprintf(L_JUNK,
             "%s: voice_handle_event got event %s with data <%s>",
             program_name,
             event_name(event),
             data.c ? buffer
                    : "NUL");

     if ((event == FAX_CALLING_TONE) && (cvd.ignore_fax_dle.d.i))
          return(OK);

     if ((result = voice_shell_handle_event(event, data)) != UNKNOWN_EVENT)
          return(result);

     if (program_handle_event != NULL)

          if ((result = program_handle_event(event, data)) != UNKNOWN_EVENT)
               return(result);

     switch (event)
          {
          case SIGNAL_SIGHUP:
          case SIGNAL_SIGINT:
          case SIGNAL_SIGQUIT:
          case SIGNAL_SIGTERM:
               lprintf(L_MESG, "%s: Received signal to terminate",
                program_name);
               voice_stop_current_action();
               voice_set_device(NO_DEVICE);
               voice_mode_off();
               voice_close_device();
               voice_unregister_event_handler();
               exit(99);
          };

     switch (voice_modem_state)
          {
          case DIALING:

               switch (event)
                    {
                    case BUSY_TONE:
                    case DATA_CALLING_TONE:
                    case FAX_CALLING_TONE:
                         return(voice_stop_dialing());
                    };

               break;
          case PLAYING:

               switch (event)
                    {
                    case LOOP_BREAK: /* This is hangup */
                    case BUSY_TONE:
                    case DIAL_TONE:
                    case DATA_CALLING_TONE:
                    case FAX_CALLING_TONE:
                    case HANDSET_OFF_HOOK:
                    case HANDSET_ON_HOOK:
                         return(voice_stop_playing());
                    };

               break;
          case RECORDING:

               switch (event)
                    {
                    case LOOP_BREAK: /* This is hangup */
                    case BUSY_TONE:
                    case DIAL_TONE:
                    case DATA_CALLING_TONE:
                    case FAX_CALLING_TONE:
                    case NO_VOICE_ENERGY:
                    case SILENCE_DETECTED:
                    case HANDSET_OFF_HOOK:
                    case HANDSET_ON_HOOK:
                         return(voice_stop_recording());
                    };

               break;
	       
	       // juergen.kosel@gmx.de : voice-duplex-patch start

	  case DUPLEXMODE:
               switch (event)
                    {
                    case LOOP_BREAK: /* This is hangup */
                    case BUSY_TONE:
                    case DIAL_TONE:
                    case DATA_CALLING_TONE:
                    case FAX_CALLING_TONE:
                    case NO_VOICE_ENERGY:
                    case SILENCE_DETECTED:
                         return(voice_stop_duplex());
                    };
	       break;
	       // juergen.kosel@gmx.de : voice-duplex-patch end

          case WAITING:

               switch (event)
                    {
                    case LOOP_BREAK: /* This is hangup */
                    case BUSY_TONE:
                    case DIAL_TONE:
                    case DATA_CALLING_TONE:
                    case FAX_CALLING_TONE:
                    case RING_DETECTED:
                         return(voice_stop_waiting());
                    };

               break;
          };

     if (event == RESET_WATCHDOG)
          {
          alarm(cvd.watchdog_timeout.d.i);
          return(OK);
          }

     buffer[0] = data.c;
     lprintf(L_JUNK,
             "%s: voice_handle_event got unknown event %s with data <%s>",
             program_name, event_name(event), data.c ? buffer : "NUL");

     return(UNKNOWN_EVENT);
     }

void voice_check_events(void)
     {
     event_type* event;

     while ((event = unqueue_event()) != NULL)
          {

          if (voice_handle_event(event->event, event->data) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not handle event, something failed", program_name);
               exit(99);
               };

          clear_event(event);
          };

     }

int voice_stop_current_action(void)
     {

     switch (voice_modem_state)
          {
          case DIALING:
               return(voice_stop_dialing());
          case PLAYING:
               return(voice_stop_playing());
          case RECORDING:
               return(voice_stop_recording());
          case WAITING:
               return(voice_stop_waiting());
	       // juergen.kosel@gmx.de : voice-duplex-patch start
	  case DUPLEXMODE:
	    return(voice_stop_duplex());
	    // juergen.kosel@gmx.de : voice-duplex-patch end
          };

     return(OK);
     }

int voice_register_event_handler(int (*new_program_handle_event) (int event,
 event_data data))
     {
     program_handle_event = new_program_handle_event;
     return(OK);
     }

int voice_unregister_event_handler(void)
     {
     program_handle_event = NULL;
     return(OK);
     }

event_type* create_event(int event)
     {
     event_type* new_event;

     new_event = malloc(sizeof(event_type));

     if (new_event != NULL)
          new_event->event = event;
     else
          lprintf(L_WARN, "%s: Could not allocate memory for event record", program_name);

     return(new_event);
     }

void clear_event(event_type* event)
     {

     if (event != NULL)
          free(event);

     event = NULL;
     }

int queue_event(event_type* event)
     {
     int event_number = last_event;

     event_queue[event_number].write_lock++;
     event_count++;

     if (event_count >= MAX_EVENTS)
          {
          lprintf(L_WARN, "%s: event queue full, ignoring event", program_name);
          event_queue[event_number].write_lock--;
          event_count--;
          return(FAIL);
          };

     while(event_queue[event_number].write_lock > 1)
          {
          event_queue[event_number].write_lock--;
          event_number = (event_number + 1) % MAX_EVENTS;
          event_queue[event_number].write_lock++;
          };

     last_event = (last_event + 1) % MAX_EVENTS;
     event_queue[event_number].event = event;
     event_queue[event_number].write_lock--;
     lprintf(L_JUNK, "%s: queued event %s at position %04d", program_name, event_name(event->event),
      event_number);
     return(OK);
     }

event_type* unqueue_event(void)
     {
     int event_number = first_event;

     event_queue[event_number].read_lock++;
     event_count--;

     if (event_count < 0)
          {
          event_queue[event_number].read_lock--;
          event_count++;
          return(NULL);
          };

     while(event_queue[event_number].read_lock > 1)
          {
          event_queue[event_number].read_lock--;
          event_number = (event_number + 1) % MAX_EVENTS;
          event_queue[event_number].read_lock++;
          };

     if (event_queue[event_number].write_lock > 0)
          {
          event_queue[event_number].read_lock--;
          event_count++;
          return(NULL);
          };

     first_event = (first_event + 1) % MAX_EVENTS;
     event_queue[event_number].read_lock--;
     lprintf(L_JUNK, "%s: unqueued event %s at position %04d", program_name,
      event_name(event_queue[event_number].event->event), event_number);
     return(event_queue[event_number].event);
     }
