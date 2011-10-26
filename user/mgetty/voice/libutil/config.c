/*
 * config.c
 *
 * This file is responsible for setting the vgetty, vm and pvf tools
 * options to a default value. Then it parses the configuration file and
 * after that the command line options.
 *
 * $Id: config.c,v 1.4 1998/09/09 21:07:09 gert Exp $
 *
 */

#include "../include/voice.h"

/*
 * Define the configuration data structure.
 */

#define CONFIG_C
#include "../include/config.h"

int rom_release = 0;
voice_modem_struct *voice_modem;
int voice_modem_state = IDLE;
char *program_name = NULL;
int voice_fd = NO_VOICE_FD;
int messages_waiting_ack = 0;
char voice_config_file[VOICE_BUF_LEN] = "";

int voice_config (char *new_program_name, char *DevID)
     {
     char *log_path = NULL;

     program_name = new_program_name;
     voice_modem = &no_modem;
     make_path(voice_config_file, CONF_DIR, VOICE_CONFIG_FILE);
     lprintf(L_MESG, "reading generic configuration from config file %s",
      voice_config_file);
     get_config(voice_config_file, (conf_data *) &cvd, "part", "generic");
     log_set_llevel(cvd.voice_log_level.d.i);

     if (strcmp(program_name, "vm") == 0)
          log_path = VM_LOG_PATH;

     if (strcmp(program_name, "vgetty") != 0)
          {
          log_init_paths(program_name, log_path, NULL);
          lprintf(L_MESG, "vgetty: %s", vgetty_version);
          }

     lprintf(L_MESG, "reading program %s configuration from config file %s",
      program_name, voice_config_file);
     get_config(voice_config_file, (conf_data *) &cvd, "program",
      program_name);
     log_set_llevel(cvd.voice_log_level.d.i);

     if (strcmp(program_name, "vgetty") == 0)
          {
          lprintf(L_MESG, "reading port %s configuration from config file %s",
           DevID, voice_config_file);
          get_config(voice_config_file, (conf_data *) &cvd, "port", DevID);
          log_set_llevel(cvd.voice_log_level.d.i);
          };

     return(OK);
     }
