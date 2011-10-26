/* event.c
 *
 * This is the handle event routine for the VoiceModem program.
 *
 * $Id: event.c,v 1.5 2001/01/14 14:33:01 marcs Exp $
 *
 */

#include "vm.h"

int handle_event(int event, event_data data)
     {

     if ((use_on_hook_off_hook) && (event == HANDSET_OFF_HOOK) &&
      (voice_modem_state == WAITING))
          {
          voice_stop_waiting();
          start_action = TRUE;
          };

     if ((use_on_hook_off_hook) && (event == HANDSET_ON_HOOK) &&
      (voice_modem_state == RECORDING)) 
          {
          voice_stop_recording();
          };

     if ((use_on_hook_off_hook) && (event == HANDSET_ON_HOOK) &&
			(voice_modem_state == PLAYING))
          {
          voice_stop_playing();
          };

     if ((event == HANDSET_OFF_HOOK) || (event == HANDSET_ON_HOOK))
          return(OK);

     if (event == RECEIVED_DTMF)

          switch (dtmf_mode)
               {
               case IGNORE_DTMF:
                    return(OK);
               case READ_DTMF_DIGIT:
                    printf("%c\n", data.c);
                    voice_stop_current_action();
                    return(OK);
               case READ_DTMF_STRING:
		    {
                       int length;

		       if (data.c == '*')
			    {
			    dtmf_string_buffer[0] = 0x00;
			    return(OK);
			    };

		       length = strlen(dtmf_string_buffer);
		       if ((data.c != '#') && (length <  (VOICE_BUF_LEN - 1)))
			    {
			    dtmf_string_buffer[length + 1] = 0x00;
			    dtmf_string_buffer[length] = data.c;
			    return(OK);
			    };

		       printf("%s\n", dtmf_string_buffer);
		       voice_stop_current_action();
		       return(OK);
                    }
               };

     if (event == SIGNAL_SIGINT)
          return(voice_stop_current_action());

     return(UNKNOWN_EVENT);
     }




