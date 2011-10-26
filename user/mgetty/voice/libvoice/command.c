/*
 * command.c
 *
 * Execute the given command and wait for an answer.
 *
 * $Id: command.c,v 1.4 1998/09/09 21:07:27 gert Exp $
 *
 */

#include "../include/voice.h"

int voice_command(char *command, char *expected_answer)
     {
     char buffer[VOICE_BUF_LEN];
     int result = VMA_FAIL;

     lprintf(L_NOISE, "voice command: '%s' -> '%s'", command,
      expected_answer);

     if (cvd.command_delay.d.i != 0)
          delay(cvd.command_delay.d.i);

     if (strlen(command) != 0)
          {

          if (voice_write("%s", command) != OK)
               {
               voice_flush(1);
               return(VMA_FAIL);
               };

          if (cvd.enable_command_echo.d.i)

               do
                    {

                    if (voice_read(buffer) != OK)
                         {
                         voice_flush(1);
                         return(VMA_FAIL);
                         };

                    result = voice_analyze(buffer, command, TRUE);

                    if (result == VMA_FAIL)
                         {
                         lprintf(L_WARN,
                          "%s: Modem did not echo the command", program_name);
                         voice_flush(1);
                         return(VMA_FAIL);
                         };

                    if (result == VMA_ERROR)
                         {
                         lprintf(L_WARN, "%s: Modem returned ERROR",
                          program_name);
                         voice_flush(1);
                         return(VMA_FAIL);
                         };

                    }
               while (result != VMA_USER_1);

          result = OK;
          };

     if (strlen(expected_answer) != 0)
          {

          do
               {

               if (voice_read(buffer) != OK)
                    {
                    voice_flush(1);
                    return(VMA_FAIL);
                    };

               result = voice_analyze(buffer, expected_answer, FALSE);

               if (result == VMA_FAIL)
                    {
                    lprintf(L_WARN, "%s: Invalid modem answer",
                     program_name);
                    voice_flush(1);
                    return(VMA_FAIL);
                    };

               if (result == VMA_ERROR)
                    {
                    lprintf(L_WARN, "%s: Modem returned ERROR",
                     program_name);
                    voice_flush(1);
                    return(VMA_FAIL);
                    };

               }
          while ((result & VMA_USER) != VMA_USER);

          };

     return(result);
     }
