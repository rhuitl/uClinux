/*
 * mode.c
 *
 * Contains the functions voice_mode_on and voice_mode_off.
 *
 * $Id: mode.c,v 1.5 1999/11/13 11:09:37 marcs Exp $
 *
 */

#include "../include/voice.h"

int voice_mode_on(void)
     {
     lprintf(L_NOISE, "%s: entering voice mode", program_name);
     tio_set(voice_fd, &voice_tio);
     voice_install_signal_handler();
     voice_modem->voice_mode_on();
     return(OK);
     }

int voice_mode_off(void)
     {
     lprintf(L_NOISE, "%s: leaving voice mode", program_name);
     voice_modem->voice_mode_off();
     voice_restore_signal_handler();
     tio_set(voice_fd, &tio_save);
     return(OK);
     }

/* Some reasons for this complicated function: (gert)
 *    - AT+FCLASS=0 means "modem is in data mode".
 *
 *    - AT+FCLASS=2 means "modem is in fax mode", which can be fax-only or
 *		    fax/data, according to +FAA:
 *
 *	  AT+FAA=1 means "adaptive answering".  An incoming call may be
 *		   fax OR data, and is answered accordingly.
 *
 *	  AT+FAA=0 means "adaptive answering OFF" -> fax ONLY.
 *
 *    Now, it's not really clear what the meaning of "+FAA=<x>" is for
 *    +FCLASS=0 mode.
 *
 *	- ZyXEL and many others make no difference in answering calls 
 *	  between +FCLASS=0 and +FCLASS=2 *if* +FAA=1 is set -> in both
 *	  cases, the modem will answer fax AND data calls properly.
 *	  If +FAA=0 and +FCLASS=0, the modem is in "data only" mode.
 *
 *	- Quite a number of Rockwell based modems work much better in 
 *	  recognizing fax and data calls when in "+FCLASS=0;+FAA=1" mode
 *	  as when in "+FCLASS=2;+FAA=1" mode.  Heaven knows why.  So that's
 *	  the default mode for class 2 modems.
 *
 *	- There are a *few* modems that interpret "+FCLASS=0;+FAA=1" as
 *	  "+FCLASS=0 -> data, so we'll do DATA ONLY", regardless of +FAA=1.  
 *	  For those, we have modem-quirks 0x01, meaning "use +FCLASS=2;+FAA=1"
 *	  to make sure we get "fax *and* data mode".
 *
 *    And then, there are some modems that just can't do +FAA=1 properly -
 *    if in +FCLASS=2 mode, they will do "fax only", and in +FCLASS=0 mode,
 *    they will do "data only".  For those modems, fax and data will only
 *    work if the modem can detect the calling tones properly when in voice
 *    mode, and report the correct <DLE> code back... otherwise, you're SOL.
 */
int enter_data_fax_mode(int answer_mode)
     {
     int bit_order = 0;
     char *fax_mode = NULL;

     lprintf(L_JUNK, "%s: asked %s%s%s",
             program_name,
             (answer_mode & ANSWER_DATA) ? "DATA" : "",
             ((answer_mode & (ANSWER_DATA|ANSWER_FAX))
              == (ANSWER_DATA|ANSWER_FAX)) ? "/" : "",
             (answer_mode & ANSWER_FAX) ? "FAX" : "");

     answer_mode &= (ANSWER_DATA | ANSWER_FAX);

     if (answer_mode == 0)
          {
          lprintf(L_NOISE,
           "%s: answer mode is set to not accept data or fax connections",
           program_name);
          return (FAIL); /* this was exit(99) from answer.c */
          };

     if (modem_type == Mt_class2)
          {
          bit_order = 0;
          fax_mode = "2";
          };

     if (modem_type == Mt_class2_0)
          {
          bit_order = 1;
          fax_mode = "2.0";
          };

     if ((modem_type == Mt_data) || (fax_mode == NULL))
          answer_mode &= ANSWER_DATA;

     if (answer_mode == 0)
          {
          lprintf(L_NOISE, "%s: modem does not support wanted mode",
           program_name);
          return(FAIL);
          };

     switch (answer_mode)
          {
          case ANSWER_DATA | ANSWER_FAX:
               lprintf(L_JUNK, "%s: trying data and fax connection",
                program_name);

	       /* Here were we moved the patch for class 2 modems:
		* following the specs, we are in +FCLASS=2;+FAA=1, but
		* there is a fair number of Rockwell modems that can't do
		* data calls if in that mode - must go to +FCLASS=0;+FAA=1 -
		* but yet other modems NEED class 2, so use modem_quirks...
                */
               if (modem_type == Mt_class2)
                    fax_mode = ( modem_quirks & MQ_NEED2 ) ? "2": "0";

               if (voice_switch_to_data_fax(fax_mode) == FAIL)
                    return(FAIL);

               if (voice_command("AT+FAA=1", "OK") != VMA_USER_1)
                    return(FAIL);

               tio_set(voice_fd, &tio_save);
               voice_restore_signal_handler();
               fax_set_bor(voice_fd, bit_order);
               break;
          case ANSWER_DATA:
               lprintf(L_JUNK, "%s: trying data connection", program_name);

               if (voice_switch_to_data_fax("0") == FAIL)
                    return(FAIL);

               if (voice_command("AT+FAA=0", "OK") != VMA_USER_1)
                    return(FAIL);

               tio_set(voice_fd, &tio_save);
               voice_restore_signal_handler();
               break;
          case ANSWER_FAX:
               lprintf(L_JUNK, "%s: trying fax connection", program_name);

               if (voice_switch_to_data_fax(fax_mode) == FAIL)
                    return(FAIL);

               if (voice_command("AT+FAA=0", "OK") != VMA_USER_1)
                    return(FAIL);

               tio_set(voice_fd, &tio_save);
               voice_restore_signal_handler();
               fax_set_bor(voice_fd, bit_order);
               break;
          };

     return(OK);
     }
