/*
 * button.c
 *
 * Mgetty calls vgetty_button when it detects, that the Data/Voice button
 * on a ZyXEL modem was pressed.
 *
 * If the phone didn't ring, vgetty calls the button_program to play
 * the received voice messages. Otherwise vgetty leaves the voice mode
 * and tries a data or fax connection.
 *
 * $Id: button.c,v 1.4 1998/09/09 21:08:06 gert Exp $
 *
 */

#include "../include/voice.h"

void vgetty_button(int rings)
     {

     if ((rings == 0) && (strlen(cvd.button_program.d.p) != 0))
          {
          char file_name[VOICE_BUF_LEN];

          make_path(file_name, cvd.voice_dir.d.p,
           cvd.button_program.d.p);
          voice_mode_on();
          voice_execute_shell_script(file_name, NULL);
          voice_mode_off();
          exit(0);
          };

     }
