/*
 * flush.c
 *
 * Read input from the voice modem device until (timeout * 0.1 seconds)
 * have passed without a new character arrived.
 *
 * $Id: flush.c,v 1.4 1998/09/09 21:07:31 gert Exp $
 *
 */

#include "../include/voice.h"

void voice_flush(int timeout)
     {
     int modem_byte;
     int first_char = TRUE;

     do
          {

          while ((modem_byte = voice_read_byte()) >= 0)
               {

               if ((modem_byte == 0x0a) || (modem_byte == 0x0d))
                    first_char = TRUE;
               else

                    if (first_char)
                         {
                         first_char = FALSE;
                         lprintf(L_JUNK, "%s: %c", voice_modem_name, modem_byte);
                         }
                    else
                         lputc(L_JUNK, modem_byte);

               }

          if (timeout > 0)
               delay(100 * timeout);

          }
     while (voice_check_for_input());

     }
