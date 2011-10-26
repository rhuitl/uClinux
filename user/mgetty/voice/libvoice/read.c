/*
 * read.c
 *
 * Read data from the voice modem device.
 *
 * $Id: read.c,v 1.4 1998/09/09 21:07:34 gert Exp $
 *
 */

#include "../include/voice.h"

static unsigned char input_buffer[1024];
static int input_pos = 0;
static int input_count = 0;

int voice_read(char *buffer)
     {
     int char_read;
     int number_chars = 0;

     lprintf(L_JUNK, "%s: ", voice_modem_name);
     strcpy(buffer, "");

     do
          {

          if ((char_read = voice_read_char()) == FAIL)
               return(FAIL);

          if (char_read == DLE)
               {

               if ((char_read = voice_read_char()) == FAIL)
                    return(FAIL);

               lputs(L_JUNK, "<DLE> <");
               lputc(L_JUNK, char_read);
               lputc(L_JUNK, '>');
               voice_modem->handle_dle(char_read);
               lprintf(L_JUNK, "%s: ", voice_modem_name);
               return(OK);
               }
          else

               if ((char_read != NL) && (char_read != CR) && (char_read != XON) && (char_read != XOFF))
                    {
                    *buffer = char_read;
                    buffer++;
                    number_chars++;
                    lputc(L_JUNK, char_read);
                    };

          }
     while (((char_read != NL) || (number_chars == 0)) && (number_chars < (VOICE_BUF_LEN - 1)));

     *buffer = 0x00;
     return(OK);
     }

int voice_read_char(void)
     {
     time_t timeout;

     timeout = time(NULL) + cvd.port_timeout.d.i;

     while (timeout >= time(NULL))
          {
          int result;

          result = voice_read_byte();

          if (result >= 0)
               return(result);

          if ((result < 0) && ((result != -EINTR) && (result != -EAGAIN)))
               {
               lprintf(L_WARN, "%s: could not read character from voice modem", program_name);
               return(FAIL);
               };

          delay(cvd.poll_interval.d.i);
          };

     lprintf(L_WARN, "%s: timeout while reading character from voice modem", program_name);
     return(FAIL);
     }

int voice_read_byte(void)
     {

     if (input_pos >= input_count)
          {
          input_count = read(voice_fd, input_buffer, sizeof(input_buffer));

          if (input_count < 0)
               return(-errno);

          if (input_count == 0)
               return(-EAGAIN);

          input_pos = 0;
          }

     return(input_buffer[input_pos++]);
     }

int voice_check_for_input(void)
     {

     if (input_pos < input_count)
          return(TRUE);

     input_count = read(voice_fd, input_buffer, sizeof(input_buffer));

     if (input_count <= 0)
          return(FALSE);

     input_pos = 0;
     return(TRUE);
     }
