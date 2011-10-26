/*
 * open.c
 *
 * Try all available voice devices and open the first one that
 * suceeds and initialize it.
 *
 * $Id: open.c,v 1.7 2002/02/25 12:19:57 gert Exp $
 *
 */

#include "../include/voice.h"

int voice_open_device(void)
     {
     char *voice_tty_start;
     char *voice_tty_end;
     char voice_tty[VOICE_BUF_LEN];

     lprintf(L_MESG, "opening voice modem device");

     if (strlen(cvd.voice_devices.d.p) == 0)
          {
          lprintf(L_WARN,
           "no voice modem devices configured in config file");
          exit(FAIL);
          };

     lprintf(L_NOISE, "voice open '%s'", cvd.voice_devices.d.p);
     voice_tty_start = cvd.voice_devices.d.p;

     do
          {
          voice_tty_end = strchr(voice_tty_start, ':');
          sprintf(voice_tty, "/dev/");

          if (voice_tty_end != NULL)
               strncat(voice_tty, voice_tty_start, voice_tty_end -
                voice_tty_start);
          else
               strcat(voice_tty, voice_tty_start);

          lprintf(L_JUNK, "trying device '%s'", voice_tty);

          if (makelock(&voice_tty[5]) == OK)
               {

               if ((voice_fd = open(voice_tty, O_RDWR | O_NDELAY | O_NOCTTY)) == FAIL)
                    {
                    lprintf(L_ERROR, "error opening %s", voice_tty);
                    rmlocks();
                    voice_fd = NO_VOICE_FD;
                    }
               else
                    lprintf(L_MESG, "opened voice modem device %s", voice_tty);

               };

          voice_tty_start = voice_tty_end + 1;
          }
     while ((voice_tty_end != NULL) && (voice_fd == NO_VOICE_FD));

     if (voice_fd != NO_VOICE_FD)
          {
	  char * p = voice_tty;
	  if ( strncmp( p, "/dev/", 5 ) == 0 ) p+=5;

          DevID = malloc(strlen(p) + 1);
          strcpy(DevID, p);
	  for( p=DevID; *p; p++) if (*p == '/') *p='-';

          lprintf(L_MESG, "reading port %s configuration from config file %s",
           &voice_tty[5], voice_config_file);
          get_config(voice_config_file, (conf_data *) &cvd, "port",
           &voice_tty[5]);
          return(voice_init());
          };

     return(FAIL);
     }
