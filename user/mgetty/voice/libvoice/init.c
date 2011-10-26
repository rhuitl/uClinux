/*
 * init.c
 *
 * Initialize the open port to some sane defaults, detect the
 * type of voice modem connected and initialize the voice modem.
 *
 * $Id: init.c,v 1.5 2001/01/29 22:38:03 gert Exp $
 */

#include "../include/voice.h"

TIO tio_save;
TIO voice_tio;

int voice_init(void)
     {

     /*
      * initialize baud rate, software or hardware handshake, etc...
      */

     tio_get(voice_fd, &tio_save);
     tio_get(voice_fd, &voice_tio);
     tio_mode_sane(&voice_tio, TRUE);

     if (tio_check_speed(cvd.port_speed.d.i) >= 0)
          {
          tio_set_speed(&voice_tio, cvd.port_speed.d.i);
          tio_set_speed(&tio_save, cvd.port_speed.d.i);
          }
     else
          {
          lprintf(L_WARN, "invalid port speed: %d", cvd.port_speed.d.i);
          close(voice_fd);
          rmlocks();
          exit(FAIL);
          }

     tio_default_cc(&voice_tio);
     tio_mode_raw(&voice_tio);
     tio_set_flow_control(voice_fd, &voice_tio, DATA_FLOW);
     voice_tio.c_cc[VMIN] = 0;
     voice_tio.c_cc[VTIME] = 0;

     if (tio_set(voice_fd, &voice_tio) == FAIL)
          {
          lprintf(L_WARN, "error in tio_set");
          close(voice_fd);
          rmlocks();
          exit(FAIL);
          };

     if (voice_detect_modemtype() == OK)
          {
          voice_flush(1);

          if (voice_mode_on() != OK)
               {
               close(voice_fd);
               rmlocks();
               return(FAIL);
               }

          if (voice_modem->init() != OK)
               {
               close(voice_fd);
               rmlocks();
               return(FAIL);
               }

          if (voice_mode_off() == OK)
               return(OK);

          }

     close(voice_fd);
     rmlocks();
     return(FAIL);
     }
