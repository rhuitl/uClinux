/*
 * write.c
 *
 * Write data to the voice modem device.
 *
 * $Id: write.c,v 1.6 2000/06/11 16:24:41 marcs Exp $
 *
 */

#include "../include/voice.h"

#if !defined(NeXT) || defined(NEXTSGTTY)
# ifdef USE_VARARGS
#  include <varargs.h>
# else
#  include <stdarg.h>
# endif
#else
# include "../include/NeXT.h"
#endif

#ifdef USE_VARARGS
int voice_write(format, va_alist)
     const char *format;
     va_dcl
#else
int voice_write(const char *format, ...)
#endif

     {
     va_list arguments;
     char command[VOICE_BUF_LEN];

#ifdef USE_VARARGS
     va_start(arguments);
#else
     va_start(arguments, format);
#endif

     vsprintf(command, format, arguments);
     va_end(arguments);
     lprintf(L_JUNK, "%s: %s", program_name, command);

     if (voice_write_raw(command, strlen(command)) == FAIL)
          return(FAIL);

     if (voice_write_char(CR) == FAIL)
          return(FAIL);

     return(OK);
     }

int voice_write_char(char charout)
     {
     time_t timeout;

     timeout = time(NULL) + cvd.port_timeout.d.i;

     while (timeout >= time(NULL))
          {
          int result;

          result = write(voice_fd, &charout, 1);

          if (result == 1)
               return(OK);

          if ((result < 0) && (errno != 0) && (errno != EINTR) && (errno !=
           EAGAIN))
               {
               lprintf(L_WARN, "%s: could not write character to voice modem",
                program_name);
               return(FAIL);
               };

          };

     lprintf(L_WARN, "%s: timeout while writing character to voice modem",
      program_name);
     return(FAIL);
     }

int voice_write_raw(char *buffer, int count)
     {
     time_t timeout;
     int result;

     timeout = time(NULL) + cvd.port_timeout.d.i;

     while ((timeout >= time(NULL)) && (count > 0))
          {
          result = write(voice_fd, buffer, count);

          if ((result < 0) && (errno != 0) && (errno != EINTR) && (errno !=
           EAGAIN))
               {
               lprintf(L_WARN, "%s: could not write buffer to voice modem",
                program_name);
               return(FAIL);
               };

          if (result > 0)
               {
               buffer += result;
               count -= result;
               };

          if (result == 0 || (result < 0 && errno == EAGAIN))
               delay(cvd.poll_interval.d.i);

          voice_check_events();
          };

     if (count == 0)
          return(OK);

     lprintf(L_WARN, "%s: timeout while writing buffer to voice modem",
      program_name);
     return(FAIL);
     }
