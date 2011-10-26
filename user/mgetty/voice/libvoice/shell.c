/*
 * shell.c
 *
 * Executes the shell script given as the argument. If the argument is
 * empty, commands are read from standard input.
 *
 * $Id: shell.c,v 1.18 2002/02/19 10:25:23 gert Exp $
 *
 */

#include "../include/voice.h"

static int events_to_shell = FALSE;
int voice_shell_state = OFF_LINE;
int voice_shell_linger = 0;
static int voice_shell_input_fd = NO_VOICE_FD;
static int voice_shell_output_fd = NO_VOICE_FD;
static int child_pid = 0;
static int level = 0;
static int autostop = FALSE;
const char ErrorString[] = "ERROR";
const char ReadyString[] = "READY" ;
const char Device_not_avail_String[] = "DEVICE_NOT_AVAILABLE" ;

int voice_execute_shell_script(char *shell_script, char **shell_options)
     {
     int arg_index = 0;
     int start_index;
     char **shell_arguments;
     int should_close_2 = 0;

     if (strlen(shell_script) == 0)
          lprintf(L_MESG, "%s: Executing shell %s", program_name, shell_script, cvd.voice_shell.d.p);
     else
          lprintf(L_MESG, "%s: Executing shell script %s with shell %s", program_name, shell_script,
           cvd.voice_shell.d.p);

     if (cvd.voice_shell_log.d.p && ((char *) cvd.voice_shell_log.d.p)[0])
     {
        char log_file_name[MAXPATH];

	if ( strlen( cvd.voice_shell_log.d.p ) + strlen( DevID ) + 5 > 
	       sizeof( log_file_name ) )
	{
	    lprintf( L_WARN, "%s: path name for shell log too long - ignoring",
			program_name );
	}
        else {
           int shell_stderr_fd;

	   sprintf( log_file_name, cvd.voice_shell_log.d.p, DevID );

           shell_stderr_fd = open(log_file_name,
                                      O_WRONLY | O_CREAT | O_APPEND, 0600);

	   /* FIXME: this really should go after the fork() call, as
	    * it will destroy vgetty's fd = 2, which might be needed
	    * later on (if the call switches to data, and we hand over
	    * to /bin/login and /bin/sh later) - gert.
	    */
           if (shell_stderr_fd != -1) {
	      /* This means we are going to close the old fd 2 if any */
	      if (dup2(shell_stderr_fd, 2) == -1)
	      {
		 lprintf(L_ERROR, "%s: couldn't dup2() shell log file",
			 program_name);
	      }
	      else {
		 should_close_2 = 1;
	      }

	      close(shell_stderr_fd);
           }
           else {
              lprintf(L_ERROR,
                      "%s: couldn't open() shell log file %s",
                      program_name,
                      log_file_name);
           }
        }
     }

     if (getenv("VOICE_PID") == NULL)
          {
          int parent_pid = getpid();
          int pipe_in[2];
          int pipe_out[2];

          lprintf(L_JUNK, "%s: opening pipes", program_name);

          if (pipe(pipe_in))
               {
               lprintf(L_WARN, "%s: cannot open input pipe!", program_name);
               return(FAIL);
               };

          if (pipe(pipe_out))
               {
               lprintf(L_WARN, "%s: cannot open output pipe!", program_name);
               return(FAIL);
               };

          lprintf(L_JUNK, "%s: forking shell", program_name);

          switch((child_pid = fork()))
               {
               case -1:
                    lprintf(L_WARN, "%s: cannot fork!", program_name);
                    return(FAIL);
		    break;
               case 0:
                    {
                    char buffer1[VOICE_BUF_LEN];
                    char buffer2[VOICE_BUF_LEN];
                    char buffer3[VOICE_BUF_LEN];
                    char buffer4[VOICE_BUF_LEN];

/*
                    if (strcmp(program_name, "vgetty") == 0)
                         {
                         close(STDIN_FILENO);
                         close(STDOUT_FILENO);
                         close(STDERR_FILENO);
                         }
                    else
                         close(voice_fd);
*/
                    close(pipe_in[1]);
                    close(pipe_out[0]);
                    sprintf(buffer1, "VOICE_PID=%d", parent_pid);
                    putenv(buffer1);
                    sprintf(buffer2, "VOICE_PROGRAM=%s", program_name);
                    putenv(buffer2);
                    sprintf(buffer3, "VOICE_INPUT=%d", pipe_in[0]);
                    putenv(buffer3);
                    sprintf(buffer4, "VOICE_OUTPUT=%d", pipe_out[1]);
                    putenv(buffer4);
                    break;
                    };
               default:
                    {
                    int child_status;

                    voice_shell_input_fd = pipe_out[0];
                    voice_shell_output_fd = pipe_in[1];
                    close(pipe_in[0]);
                    close(pipe_out[1]);

                    if (should_close_2) {
                       close(2); /* from the dup2 */
                    }

                    if (voice_write_shell("HELLO SHELL") != OK)
                         return(FAIL);

                    voice_shell_state = INITIALIZING;

                    while ((wait(&child_status) == -1) && (errno == EINTR))
                         voice_check_events();

                    voice_shell_state = OFF_LINE;
                    close(voice_shell_input_fd);
                    close(voice_shell_output_fd);

                    if (WIFEXITED(child_status) != 0)
                         {
                         child_status = WEXITSTATUS(child_status);
                         lprintf(L_NOISE,
                          "%s: shell exited normally with status 0x%04x",
                          program_name, child_status);
                         return(child_status);
                         };

                    lprintf(L_NOISE,
                     "%s: shell exited not normally with status 0x%x",
                     program_name, child_status);
                    return(FAIL);
                    };
               };

          };

     if (shell_options != NULL)

          for (arg_index = 0; shell_options[arg_index] != NULL; arg_index++)
               ;

     shell_arguments = (char**) malloc((3 + arg_index) * sizeof(char*));
     start_index = 1;
     shell_arguments[0] = cvd.voice_shell.d.p;

     if (strlen(shell_script) != 0)
          {
          start_index = 2;
          shell_arguments[1] = shell_script;
          };

     if (shell_options != NULL)

          for (arg_index = 0; shell_options[arg_index] != NULL; arg_index++)
               shell_arguments[arg_index + start_index] =
                shell_options[arg_index];

     shell_arguments[arg_index + start_index] = NULL;
     execv(cvd.voice_shell.d.p, shell_arguments);
     lprintf(L_WARN, "%s: cannot execute %s %s", program_name,
      cvd.voice_shell.d.p, shell_script);
     exit(99);
     }

/*
 *  variables to set by voice_fax.c
 */

int voice_fax_hangup_code;
char *voice_fax_remote_id;
int voice_fax_pages;
char *voice_fax_files;

int voice_shell_notify()
     {
     voice_write_shell("HUP_CODE\n%d", voice_fax_hangup_code);
     voice_write_shell("REMOTE_ID\n%s", voice_fax_remote_id);

     if (voice_fax_files != NULL) {
         char **ap, *av[100];
      char *cp = voice_fax_files;
      int i, n;

         for (ap = av, n = 0; (*ap = voice_strsep(&cp, " \t")) != NULL;)
              if (**ap != '\0') {
                   ++ap;
             ++n;
           }

         if (n > 0) {
              voice_write_shell("FAX_FILES\n%d", n);

           for (i = 0; i < n; i++)
                   voice_write_shell("%s", av[i]);

           }

         }

     return 0;
     }

int voice_shell_handle_event(int event, event_data data)
     {

     if (voice_shell_state == OFF_LINE)
          return(UNKNOWN_EVENT);

     if (event == SIGNAL_SIGCHLD)
          {
          voice_shell_state = OFF_LINE;
          voice_shell_linger = 0;
          voice_stop_current_action();
          return(OK);
          };

     if (event == SIGNAL_SIGPIPE)
          {
          char buffer[VOICE_BUF_LEN];

          level++;

          if (voice_read_shell(buffer) != OK)
               return(FAIL);

          if (voice_shell_state == INITIALIZING)
               {

               if (strcmp(buffer, "HELLO VOICE PROGRAM") != 0)
                    {
                    lprintf(L_WARN, "%s: cannot initialize communication!", program_name);
                    voice_shell_state = OFF_LINE;
                    return(FAIL);
                    };

               if (voice_write_shell(ReadyString) != OK)
                    return(FAIL);

               voice_shell_state = ON_LINE;
               lprintf(L_NOISE, "%s: initialized communication", program_name);
               }
          else
               {

               if (strncmp(buffer, "STOP", 4) == 0)
                    {

                    switch (voice_modem_state)
                         {
                         case DIALING:
                         case PLAYING:
                         case RECORDING:
                         case WAITING:
                              voice_shell_linger = 0;
                              voice_stop_current_action();
                              break;
                         case IDLE:
                              lprintf(L_NOISE, "%s: STOP during IDLE", program_name);

                              if (voice_write_shell(ReadyString) != OK)
                                   return(FAIL);

                              break;
                         default:

                              if (voice_write_shell(ErrorString) != OK)
                                   return(FAIL);

                         };

                    }
               else if (level != 1)
                    {
                    lprintf(L_MESG, "%s: Nested command in shell script", program_name);

                    if (voice_write_shell(ErrorString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "BEEP", 4) == 0)
                    {
                    int frequency = cvd.beep_frequency.d.i;
                    int length = cvd.beep_length.d.i;

                    sscanf(buffer, "%*s %d %d", &frequency, &length);

                    if (voice_write_shell("BEEPING") != OK)
                         return(FAIL);

                    if (voice_beep(frequency, length) != OK)

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "QUOTE", 5) == 0)
                    {
                    char quoted_cmd[VOICE_BUF_LEN] = "";
                    
                    sscanf(buffer, "%*s %s", quoted_cmd);

                    lprintf(L_MESG, "%s: SENDING QUOTED CMD \"%s\"",
                            program_name, quoted_cmd);
                       
                    if (voice_command(quoted_cmd, "OK") == VMA_FAIL)
                        {
                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);
                        }
                      
                    if (voice_write_shell(ReadyString) != OK)
                       return(FAIL);
                    }
               else if (strncmp(buffer, "DEVICE", 6) == 0)
                    {
                    char device[VOICE_BUF_LEN] = "";
                    int ResultCode = FAIL;

                    sscanf(buffer, "%*s %s", device);

                    if (strcmp(device, "NO_DEVICE") == 0)
		      ResultCode = voice_set_device(NO_DEVICE);
                    else if (strcmp(device, "DIALUP_LINE") == 0)
		      ResultCode = voice_set_device(DIALUP_LINE);
		    else if (strcmp(device, "INTERNAL_MICROPHONE") == 0)
		      ResultCode = voice_set_device(INTERNAL_MICROPHONE);
                    else if (strcmp(device, "EXTERNAL_MICROPHONE") == 0)
		      ResultCode = voice_set_device(EXTERNAL_MICROPHONE);
                    else if (strcmp(device, "INTERNAL_SPEAKER") == 0)
		      ResultCode = voice_set_device(INTERNAL_SPEAKER);
                    else if (strcmp(device, "EXTERNAL_SPEAKER") == 0)
		      ResultCode = voice_set_device(EXTERNAL_SPEAKER);
                    else if (strcmp(device, "LOCAL_HANDSET") == 0)
		      ResultCode = voice_set_device(LOCAL_HANDSET);
		    else if (strcmp(device, "DIALUP_WITH_EXT_SPEAKER") == 0)
		      ResultCode = voice_set_device(DIALUP_WITH_EXT_SPEAKER);
		    else if (strcmp(device, "DIALUP_WITH_INT_SPEAKER") == 0)
		      ResultCode = voice_set_device(DIALUP_WITH_INT_SPEAKER);
		    else if (strcmp(device, "DIALUP_WITH_LOCAL_HANDSET") == 0)
		      ResultCode = voice_set_device(DIALUP_WITH_LOCAL_HANDSET);
		    else if (strcmp(device, "DIALUP_WITH_EXTERNAL_MIC_AND_SPEAKER") == 0)
		      ResultCode
                      = voice_set_device(DIALUP_WITH_EXTERNAL_MIC_AND_SPEAKER);
		    else if (strcmp(device, "DIALUP_WITH_INTERNAL_MIC_AND_SPEAKER") == 0)
		      ResultCode
                      = voice_set_device(DIALUP_WITH_INTERNAL_MIC_AND_SPEAKER);
                    else if (voice_write_shell(ErrorString) != OK)
		      return(FAIL);

		    switch(ResultCode)
		      {
		      case OK:
			if (voice_write_shell(ReadyString) != OK)
			  return(FAIL);
                        break;
		      case VMA_DEVICE_NOT_AVAIL:
			if (voice_write_shell(Device_not_avail_String) != OK)
			  return(FAIL);
                        break;
		      default: /* FAIL and unknown return values */
			if (voice_write_shell(ErrorString) != OK)
			  return(FAIL);
                        break;
		      } /* switch(ResultCode) */
                    }
               else if (strncmp(buffer, "DIAL", 4) == 0)
                    {
                    char phone_number[VOICE_BUF_LEN] = "";

                    sscanf(buffer, "%*s %s", phone_number);

                    if (voice_write_shell("DIALING") != OK)
                         return(FAIL);

                    if (voice_dial((void *) phone_number) == FAIL)

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "DISABLE EVENTS", 14) == 0)
                    {
                    events_to_shell = FALSE;

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "ENABLE EVENTS", 13) == 0)
                    {
                    events_to_shell = TRUE;

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strcmp(buffer, "GET TTY") == 0)
                    {

                    if (voice_write_shell(DevID) != OK)
                         return(FAIL);

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               /* -- alborchers@steinerpoint.com */
               else if (strcmp(buffer, "GET MODEM") == 0)
                    {

                    if (voice_write_shell(voice_modem_name) != OK)
                         return(FAIL);

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strcmp(buffer, "AUTOSTOP ON") == 0)
                    {
                    autostop = TRUE;

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strcmp(buffer, "AUTOSTOP OFF") == 0)
                    {
                    autostop = FALSE;

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strcmp(buffer, "GOODBYE") == 0)
                    {

                    if (voice_write_shell("GOODBYE SHELL") != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "GETFAX", 6) == 0)
                    {
                    char path[VOICE_BUF_LEN] = "/tmp";

/*
                    if (voice_device != DIALUP_LINE)

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);
*/

                    sscanf(buffer, "%*s %s", path);

                    if (voice_write_shell("RECEIVING") != OK)
                         return(FAIL);

		    if (enter_data_fax_mode(ANSWER_FAX)
			== FAIL) {
		       lprintf(L_WARN, "%s: Could not switch to fax mode",
		               program_name);
                       /* otherwise result ignored, which is already much
                        * better than before.
                        */
		    }

                    voice_write("ATA"); /* faxrec will eat the rest */
                    voice_faxrec(path, 0);
                    voice_init();
                    voice_mode_on();
                    voice_set_device(DIALUP_LINE);
                    voice_shell_notify();

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "SENDFAX", 7) == 0)
                    {
                    char *cp = &buffer[7];
                    char **ap, *av[100];

                    for (ap = av; (*ap = voice_strsep(&cp, " \t")) != NULL;)

                         if (**ap != '\0')
                              ++ap;

                    if (av[0] != NULL)
                         {
			 if (enter_data_fax_mode(ANSWER_FAX)
			     == FAIL) {
			    lprintf(L_WARN, "%s: Could not switch to fax mode",
				    program_name);
			    /* otherwise result ignored, which is already much
			     * better than before.
			     */
			 }
                         voice_faxsnd(av, 0, 3);
                         voice_init();
                         voice_mode_on();
                         voice_set_device(DIALUP_LINE);
                         voice_shell_notify();
                         }
                    else
                         {

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);

                         }

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "PLAY", 4) == 0)
                    {
                    char name[VOICE_BUF_LEN] = "";

                    voice_shell_linger = 0; /* -- alborchers@steinerpoint.com */
                    sscanf(buffer, "%*s %s %d", name, &voice_shell_linger);

                    if (strlen(name) != 0)
                         {

                         if (voice_write_shell("PLAYING") != OK)
                              return(FAIL);

                         if (voice_play_file(name) == FAIL)

                              if (voice_write_shell(ErrorString) != OK)
                                   return(FAIL);

                         }
                    else
                         {

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);

                         }

                    voice_shell_linger = 0;

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "RECORD", 6) == 0)
                    {
                    char name[VOICE_BUF_LEN] = "";

                    sscanf(buffer, "%*s %s", name);

                    if (strlen(name) != 0)
                         {

                         if (voice_write_shell("RECORDING") != OK)
                              return(FAIL);

                         if (voice_record_file(name) != OK)

                              if (voice_write_shell(ErrorString) != OK)
                                   return(FAIL);

                         }
                    else
                         {

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);

                         }

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "WAIT", 4) == 0)
                    {
                    int length = cvd.rec_silence_len.d.i / 10;

                    sscanf(buffer, "%*s %d", &length);

                    if (voice_write_shell("WAITING") != OK)
                         return(FAIL);

                    if (voice_wait(length) != OK)

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    }
               else if (strncmp(buffer, "DTMF", 4) == 0)
                    {
                    char number[VOICE_BUF_LEN] = "";

                    sscanf(buffer, "%*s %s", number);

                    if (voice_write_shell("DTMFING") != OK)
                         return(FAIL);

                    if (voice_play_dtmf(number) == FAIL)

                         if (voice_write_shell(ErrorString) != OK)
                              return(FAIL);

                    if (voice_write_shell(ReadyString) != OK)
                         return(FAIL);

                    } 
               else
                    {

                    if (voice_write_shell(ErrorString) != OK)
                         return(FAIL);

                    }

               };

          level--;
          return(OK);
          };


     if ((voice_shell_state == ON_LINE) && (event == RECEIVED_DTMF) && autostop)

          switch (voice_modem_state)
               {
               case WAITING:
                    if( voice_shell_linger > 0 )
                        break;
               case PLAYING:
               case RECORDING:
                    lprintf(L_JUNK, "%s: stopping current action", program_name);
                    voice_stop_current_action();
                    break;
               }

     if ((voice_shell_state == ON_LINE) && (!events_to_shell) && ((event & VOICE_MODEM_EVENT) != 0))
          return(OK);

     if ((voice_shell_state == ON_LINE) && events_to_shell && ((event & VOICE_MODEM_EVENT) != 0))
          {

          switch (event)
               {
               case BONG_TONE:

                    if (voice_write_shell("BONG_TONE") != OK)
                         return(FAIL);

                    return(OK);
               case BUSY_TONE:

                    if (voice_write_shell("BUSY_TONE") != OK)
                         return(FAIL);

                    return(OK);
               case CALL_WAITING:

                    if (voice_write_shell("CALL_WAITING") != OK)
                         return(FAIL);

                    return(OK);
               case DIAL_TONE:

                    if (voice_write_shell("DIAL_TONE") != OK)
                         return(FAIL);

                    return(OK);
               case DATA_CALLING_TONE:

                    if (voice_write_shell("DATA_CALLING_TONE") != OK)
                         return(FAIL);

                    return(OK);
               case DATA_OR_FAX_DETECTED:

                    if (voice_write_shell("DATA_OR_FAX_DETECTED") != OK)
                         return(FAIL);

                    return(OK);
               case FAX_CALLING_TONE:

                    if (voice_write_shell("FAX_CALLING_TONE") != OK)
                         return(FAIL);

                    return(OK);
               case HANDSET_ON_HOOK:

                    if (voice_write_shell("HANDSET_ON_HOOK") != OK)
                         return(FAIL);

                    return(OK);
               case HANDSET_OFF_HOOK:

                    if (voice_write_shell("HANDSET_OFF_HOOK") != OK)
                         return(FAIL);

                    return(OK);
               case LOOP_BREAK:

                    if (voice_write_shell("LOOP_BREAK") != OK)
                         return(FAIL);

                    return(OK);
               case LOOP_POLARITY_CHANGE:

                    if (voice_write_shell("LOOP_POLARITY_CHANGE") != OK)
                         return(FAIL);

                    return(OK);
               case NO_ANSWER:

                    if (voice_write_shell("NO_ANSWER") != OK)
                         return(FAIL);

                    return(OK);
               case NO_CARRIER:
 
                    if (voice_write_shell("NO_CARRIER") != OK)
                         return(FAIL);
                 
                    return(OK);

               case NO_DIAL_TONE:

                    if (voice_write_shell("NO_DIAL_TONE") != OK)
                         return(FAIL);

                    return(OK);
               case NO_VOICE_ENERGY:

                    if (voice_write_shell("NO_VOICE_ENERGY") != OK)
                         return(FAIL);

                    return(OK);
               case RING_DETECTED:

                    if (voice_write_shell("RING_DETECTED") != OK)
                         return(FAIL);

                    return(OK);
               case RINGBACK_DETECTED:

                    if (voice_write_shell("RINGBACK_DETECTED") != OK)
                         return(FAIL);

                    return(OK);
               case RECEIVED_DTMF:

                    if (voice_write_shell("RECEIVED_DTMF") != OK)
                         return(FAIL);

                    if (voice_write_shell("%c", data.c) != OK)
                         return(FAIL);
                         ;
                    return(OK);
               case SILENCE_DETECTED:

                    if (voice_write_shell("SILENCE_DETECTED") != OK)
                         return(FAIL);

                    return(OK);
               case SIT_TONE:

                    if (voice_write_shell("SIT_TONE") != OK)
                         return(FAIL);

                    return(OK);
               case TDD_DETECTED:

                    if (voice_write_shell("TDD_DETECTED") != OK)
                         return(FAIL);

                    return(OK);
               case VOICE_DETECTED:

                    if (voice_write_shell("VOICE_DETECTED") != OK)
                         return(FAIL);

                    return(OK);
               };

          };

     return(UNKNOWN_EVENT);
     }

int voice_read_shell(char *buffer)
     {
     char char_read;
     int number_chars = 0;

     lprintf(L_NOISE, "shell(%d): ", level);

     do
          {

          if (read(voice_shell_input_fd, &char_read, 1) != 1)
               {
               lprintf(L_WARN, "could not read from shell");

               if (child_pid != 0)
                    kill(child_pid, SIGKILL);

               return(FAIL);
               };

          if (char_read != NL)
               {
               *buffer = char_read;
               buffer++;
               number_chars++;
               lputc(L_NOISE, char_read);
               };

          }
     while (((char_read != NL) || (number_chars == 0)) &&
      (number_chars < (VOICE_BUF_LEN - 1)));

     *buffer = 0x00;
     return(OK);
     }

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
int voice_write_shell(format, va_alist)
     const char *format;
     va_dcl
#else
int voice_write_shell(const char *format, ...)
#endif

     {
     va_list arguments;
     char answer[VOICE_BUF_LEN];

#ifdef USE_VARARGS
     va_start(arguments);
#else
     va_start(arguments, format);
#endif

     vsprintf(answer, format, arguments);
     va_end(arguments);
     lprintf(L_NOISE, "%s(%d): %s", program_name, level, answer);

     if ((write(voice_shell_output_fd, answer, strlen(answer)) !=
      strlen(answer)) || (write(voice_shell_output_fd, "\n", 1) != 1))
          {
          lprintf(L_WARN, "%s: could not write to shell", program_name);

          if (child_pid != 0)
               kill(child_pid, SIGKILL);

          return(FAIL);
          };

     return(OK);
     }
