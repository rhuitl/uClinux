/*
 * answer.c
 *
 * $Id: answer.c,v 1.22 2002/12/15 19:43:35 gert Exp $
 *
 */

#include "../include/voice.h"

int answer_mode;
char dtmf_code[VOICE_BUF_LEN];
int execute_dtmf_script;
int first_dtmf;
int hangup_requested;
int switch_to_data_fax_mode;

/* This wrapper is used for answering functions at the vgetty
 * call initialization.
 */
static int enter_data_fax_mode_wrapper(int answer_mode) {
   if (cvd.force_autodetect.d.i) {
      answer_mode = ANSWER_DATA | ANSWER_FAX;
   }

   return enter_data_fax_mode(answer_mode);
}

static int get_answer_mode(char* ring_type)
     {
     char answer_mode[VOICE_BUF_LEN] = "";
     int result = 0;

     /*
      * This is only a temporary place for the read from the config file,
      * to keep the interface to mgetty unchanged. It will move to another
      * routine in the future, that is called from mgetty after the first
      * ring, when the ring type and caller id information is available,
      * so that the number of rings to answer the phone can also be set by
      * the voice configuration file.
      */

     lprintf(L_MESG, "reading ring_type %s configuration from config file %s",
      ring_type, voice_config_file);
     get_config(voice_config_file, (conf_data *) &cvd, "ring_type", ring_type);
     strcpy(answer_mode, cvd.answer_mode.d.p);

     if (strlen(answer_mode) != 0)
          {
          int i;
          char *prefix = "";

          if (strncmp(answer_mode, "/", 1) == 0)
               {
               char answer_mode_file_name[VOICE_BUF_LEN];
               FILE *answer_mode_file;

               sprintf(answer_mode_file_name, "%s.%s",
                answer_mode, DevID);
               answer_mode_file = fopen(answer_mode_file_name, "r");

               if (answer_mode_file != NULL)
                    {
                    lprintf(L_JUNK, "%s: reading answer mode file %s",
                     program_name, answer_mode_file_name);
                    fscanf(answer_mode_file, "%s", answer_mode);
                    fclose(answer_mode_file);
                    }
               else
                    {
                    sprintf(answer_mode_file_name, "%s", answer_mode);
                    answer_mode_file = fopen(answer_mode_file_name, "r");

                    if (answer_mode_file != NULL)
                         {
                         lprintf(L_JUNK, "%s: reading answer mode file %s",
                          program_name, answer_mode_file_name);
                         fscanf(answer_mode_file, "%s", answer_mode);
                         fclose(answer_mode_file);
                         };

                    };

               }
          else
               lprintf(L_JUNK, "%s: answer mode was set directly",
                program_name);

          for (i = 0; i < strlen(answer_mode); i++)
               answer_mode[i] = tolower(answer_mode[i]);

          lprintf(L_JUNK, "%s: answer mode is [", program_name);

          if (strstr(answer_mode, "data"))
               {
               result |= ANSWER_DATA;
               lputs(L_JUNK, "data");
               prefix = "|";
               };

          if (strstr(answer_mode, "fax"))
               {
               result |= ANSWER_FAX;
               lputs(L_JUNK, prefix);
               lputs(L_JUNK, "fax");
               prefix = "|";
               };

          if (strstr(answer_mode, "voice"))
               {
               result |= ANSWER_VOICE;
               lputs(L_JUNK, prefix);
               lputs(L_JUNK, "voice");
               };

          lputs(L_JUNK, "]");
          };

     if (result == 0)
          {
          lprintf(L_NOISE,
           "%s: answer mode is set to not accept any kind of call",
           program_name);

          /*
           * Ignore everything until the phone stops ringing and exit then
           */

          voice_flush(100);
          exit(1);
          };

     return(result);
     }

static void get_greeting_message(char *message)
     {
     char message_dir[VOICE_BUF_LEN];
     char list_file_name[VOICE_BUF_LEN];
     char message_file_name[VOICE_BUF_LEN];
     FILE *list;

     strcpy(message_file_name, cvd.backup_message.d.p);
     make_path(message_dir, cvd.voice_dir.d.p, cvd.message_dir.d.p);
     make_path(list_file_name, message_dir, cvd.message_list.d.p);
     lprintf(L_JUNK, "%s: opening list file %s", program_name,
      list_file_name);
     list = fopen(list_file_name, "r");

     if (list != NULL)
          {
          int choice;
          int count = 0;
          int i;

          while (fgets(message_file_name, VOICE_BUF_LEN, list) != NULL)
               count++;

          if (count == 0)
               strcpy(message_file_name, cvd.backup_message.d.p);
          else
               {
#ifdef M_UNIX	/* SCO has no srandom */
               srand(time(NULL) | getpid());
               choice = rand() % count + 1;
#else
               srandom(time(NULL) | getpid());
               choice = random() % count + 1;
#endif
               lprintf(L_JUNK,
                "%s: found %d messages, picked message number %d",
                program_name, count, choice);
               rewind(list);

               for (i = 0; i < choice; i++)
                    fgets(message_file_name, VOICE_BUF_LEN, list);

               i = strlen(message_file_name) - 1;

               if ((i > 0) && (message_file_name[i] == NL))
                    message_file_name[i] = 0x00;

               }

          fclose(list);
          };

     make_path(message, message_dir, message_file_name);
     lprintf(L_JUNK, "%s: message name is %s", program_name, message);
     }

static void get_beep_sound(char *beepsound)
     {
     char message_dir[VOICE_BUF_LEN];
     char beep_sound_name[VOICE_BUF_LEN];

     strcpy(beep_sound_name, cvd.beepsound.d.p);
     if (!*beep_sound_name)
        {
        *beepsound = '\0';
        return;
        }
     make_path(message_dir, cvd.voice_dir.d.p, cvd.message_dir.d.p);
     make_path(beepsound, message_dir, beep_sound_name);
     lprintf(L_JUNK, "%s: beepsound name is %s", program_name, beepsound);

     }

static void get_pre_message(char *pre_message)
     {
     char message_dir[VOICE_BUF_LEN];
     char pre_message_name[VOICE_BUF_LEN];

     strcpy(pre_message_name, cvd.pre_message.d.p);
     if (!*pre_message_name)
        {
        *pre_message = '\0';
        return;
        }
     make_path(message_dir, cvd.voice_dir.d.p, cvd.message_dir.d.p);
     make_path(pre_message, message_dir, pre_message_name);
     lprintf(L_JUNK, "%s: pre_message name is %s", program_name, pre_message);

     }

static void remove_message(char *message)
     {

     if (!cvd.rec_always_keep.d.i)
          {
          lprintf(L_JUNK, "%s: removing message %s", program_name, message);
          unlink(message);
          };

     }

int vgetty_answer(int rings, int rings_wanted, int dist_ring)
     {
     time_t call_start;
     time_t call_end;
     time_t call_length;
     char greeting_message[VOICE_BUF_LEN];
     char beep_sound[VOICE_BUF_LEN];
     char pre_message[VOICE_BUF_LEN];
     char receive_dir[VOICE_BUF_LEN];
     char message[VOICE_BUF_LEN];
     char message_name[VOICE_BUF_LEN];
     char ring_type[20] = "ring";
     int i, j;
     int result;
     char c;
     pid_t pid = getpid();

     setup_environment(); /* caller ID, called ID and stuff */

     /*
      * Mapping from mgetty's answer mode detection to the new vgetty way
      */

     if (virtual_ring)
          strcpy( ring_type, "virtual" );

     if (dist_ring > 0 && dist_ring < 100000 )
	  sprintf( ring_type, "ring%d", dist_ring );

     answer_mode = get_answer_mode(ring_type);

     if ((answer_mode & ANSWER_VOICE) == 0)
          {

          if (enter_data_fax_mode_wrapper(answer_mode)
              == FAIL)
               {
               lprintf(L_WARN, "%s: Could not switch to data or fax mode",
                program_name);
               exit(99);
               }

          return(VMA_OK);
          };

     get_pre_message(pre_message);
     get_greeting_message(greeting_message);
     get_beep_sound(beep_sound);
     strcpy(dtmf_code, "");
     execute_dtmf_script = FALSE;
     first_dtmf = TRUE;
     hangup_requested = FALSE;
     switch_to_data_fax_mode = FALSE;

     if (voice_mode_on() == FAIL)
          {
          lprintf(L_WARN, "%s: Could not switch to voice mode",
           program_name);
          exit(99);
          }

     if (voice_modem_quirks() & VMQ_NEEDS_SET_DEVICE_BEFORE_ANSWER) {
       if (voice_set_device(DIALUP_LINE) != OK) {
	 lprintf(L_WARN, "%s: Could not switch to dialup line",
		 program_name);
	 exit(99);
       }
     }

     result = voice_answer_phone();
     switch (result) {
        case VMA_OK:
           /* VOICE */
           break;
        case VMA_CONNECT:
           /* DATA */
        case VMA_FCON:
           /* FAX */
        case VMA_FAX:
        case VMA_FCO:
           voice_restore_signal_handler();
           tio_set(voice_fd, &tio_save);
           return result;
           break;
        default:
           lprintf(L_WARN, "%s: Could not answer the phone. Strange...",
                           program_name);
           exit(99);
           break;
     }

     make_path(receive_dir, cvd.voice_dir.d.p, cvd.receive_dir.d.p);

     /* The file name is made from "v", then the pid, then the
      * time_t, then the possible CallerId, plus separators.
      * The caller-ID is truncated at 16 characters.
      * NOTES
      *    - On system not supporting standard file names (e.g. 14-characters
      *      sysvfs), only the pid will be used.
      */

#ifdef SHORT_FILENAMES
     sprintf(message_name, "v%u",
             pid);
#else /* !SHORT_FILENAMES */
     sprintf(message_name, "v-%u-%u",
             pid,
             (unsigned int) time(NULL));
#endif /* !SHORT_FILENAMES */

#ifndef SHORT_FILENAMES
     /* Include caller ID string in the file name */
     if (strcmp(CallerId, "none")) {
         i = strlen(message_name);
         message_name[i++] = '-';
         for (j = 0; j < 16 && CallerId[j]; j++) {
             c = CallerId[j];
             if (c == ' ' || c == '/' || c == '\\'|| c == '&' || c == ';' ||
                 c == '(' || c == ')' || c == '>' || c == '<' || c == '|' ||
                 c == '?' || c == '*' || c == '\''|| c == '"' || c == '`')
                 {
                 if (message_name[i-1] != '-')
                     message_name[i++] = '-' ;
                 }
             else
                 message_name[i++] = c;
         }
         if (message_name[i-1] == '-')
             i--;
         message_name[i] = '\0';
     }
#endif

     strcat(message_name, ".rmd");
     make_path(message, receive_dir, message_name);

     if (!(voice_modem_quirks() & VMQ_NEEDS_SET_DEVICE_BEFORE_ANSWER)) {
       if (voice_set_device(DIALUP_LINE) != OK) {
	   lprintf(L_WARN, "%s: Could not switch to dialup line",
		   program_name);
	   exit(99);
	 }
     }

     if (strlen(cvd.call_program.d.p) != 0)
          {
          char *arguments[2];
          char call_program[VOICE_BUF_LEN];
          int result;

          arguments[0] = DevID;
          arguments[1] = NULL;
          make_path(call_program, cvd.voice_dir.d.p, cvd.call_program.d.p);
          result = voice_execute_shell_script(call_program, arguments);

          if (result == FAIL)
               {
               lprintf(L_WARN, "%s: shell script %s exited unnormally",
                       program_name, call_program);
               }
          else

               switch (result)
                    {
                    case 1:

                         if (enter_data_fax_mode_wrapper
                                (answer_mode & ANSWER_DATA)
                             == FAIL)
                              {
                              lprintf(L_WARN,
                               "%s: Could not switch to data mode",
                               program_name);
                              exit(99);
                              }

                         return(VMA_OK);
                    case 2:

                         if (enter_data_fax_mode_wrapper(answer_mode & ANSWER_FAX) ==
                          FAIL)
                              {
                              lprintf(L_WARN,
                               "%s: Could not switch to fax mode",
                               program_name);
                              exit(99);
                              }

                         return(VMA_OK);
                    case 3:

                         if (enter_data_fax_mode_wrapper(answer_mode & (ANSWER_DATA |
                          ANSWER_FAX)) == FAIL)
                              {
                              lprintf(L_WARN,
                               "%s: Could not switch to data/fax mode",
                               program_name);
                              exit(99);
                              }

                         return(VMA_OK);
                    default:

                         if (voice_set_device(NO_DEVICE) != OK)
                              {
                              lprintf(L_WARN,
                               "%s: Could not hang up the line",
                               program_name);
                              exit(99);
                              }

                         if (voice_mode_off() == FAIL)
                              {
                              lprintf(L_WARN,
                               "%s: Could not turn off voice mode",
                               program_name);
                              exit(99);
                              }

                         if (voice_close_device() == FAIL)
                              {
                              lprintf(L_WARN,
                               "%s: Could not close the voice device",
                               program_name);
                              exit(99);
                              }

                         exit(0);
                    };

          };

     if (*pre_message)
          {
          if (voice_play_file(pre_message) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not play pre_message sound file",
                program_name);
               }
          }

     if (voice_play_file(greeting_message) == FAIL)
          {
          lprintf(L_WARN, "%s: Could not play greeting message",
           program_name);
          }

     if ((execute_dtmf_script) && (strlen(cvd.dtmf_program.d.p) != 0))
          {
          char *arguments[3];
          char dtmf_program[VOICE_BUF_LEN];

          arguments[0] = dtmf_code;
          arguments[1] = "none";
          arguments[2] = NULL;
          make_path(dtmf_program, cvd.voice_dir.d.p, cvd.dtmf_program.d.p);
          lprintf(L_AUDIT,
           "got DTMF code - executing DTMF program, name='%s', caller=%s, dev=%s, pid=%d",
           CallName, CallerId, DevID, getpid());
          voice_execute_shell_script(dtmf_program, arguments);

#if 0
/* selecting NO_DEVICE means to hang up the line-> so vgetty shouldn't do this! */
          if (voice_set_device(NO_DEVICE) != OK)
               {
               lprintf(L_WARN, "%s: Could not hang up the line",
                program_name);
               exit(99);
               }
#endif
          if (voice_mode_off() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not turn off voice mode",
                program_name);
               exit(99);
               }

          if (voice_close_device() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not close the voice device",
                program_name);
               exit(99);
               }

          exit(0);
          };

     if (hangup_requested)
          {
          lprintf(L_AUDIT,
           "hangup requested, name='%s', caller=%s, dev=%s, pid=%d",
           CallName, CallerId, DevID, getpid());

          if (voice_set_device(NO_DEVICE) != OK)
               {
               lprintf(L_WARN, "%s: Could not hang up the line",
                program_name);
               exit(99);
               }

          if (voice_mode_off() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not turn off voice mode",
                program_name);
               exit(99);
               }

          if (voice_close_device() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not close the voice device",
                program_name);
               exit(99);
               }

          exit(0);
          };

     if (switch_to_data_fax_mode)
          {

          if (enter_data_fax_mode_wrapper(answer_mode) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not switch to data/fax mode",
                program_name);
               exit(99);
               }

          return(VMA_OK);
          };

     if (*beep_sound)
          {
          if (voice_play_file(beep_sound) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not play beep sound file",
                program_name);
               }
          }
     else
          {
          if (voice_beep(cvd.beep_frequency.d.i, cvd.beep_length.d.i) == FAIL)
               {
               lprintf(L_WARN, "%s: Beep command failed");
               }
          }

     if ((execute_dtmf_script) && (strlen(cvd.dtmf_program.d.p) != 0))
          {
          char *arguments[3];
          char dtmf_program[VOICE_BUF_LEN];

          arguments[0] = dtmf_code;
          arguments[1] = "none";
          arguments[2] = NULL;
          make_path(dtmf_program, cvd.voice_dir.d.p, cvd.dtmf_program.d.p);
          lprintf(L_AUDIT,
           "got DTMF code - executing DTMF program, name='%s', caller=%s, dev=%s, pid=%d",
           CallName, CallerId, DevID, getpid());
          voice_execute_shell_script(dtmf_program, arguments);

#if 0
/* the dtmf program can't do anything with a disconnected line */
          if (voice_set_device(NO_DEVICE) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not hang up the line",
                program_name);
               exit(99);
               }
#endif
          if (voice_mode_off() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not turn off voice mode",
                program_name);
               exit(99);
               }

          if (voice_close_device() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not close the voice device",
                program_name);
               exit(99);
               }

          exit(0);
          };

     if (hangup_requested)
          {
          lprintf(L_AUDIT,
           "hangup requested, name='%s', caller=%s, dev=%s, pid=%d",
           CallName, CallerId, DevID, getpid());

          if (voice_set_device(NO_DEVICE) != OK)
               {
               lprintf(L_WARN, "%s: Could not hang up the line",
                program_name);
               exit(99);
               }

          if (voice_mode_off() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not turn off voice mode",
                program_name);
               exit(99);
               }

          if (voice_close_device() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not close the voice device",
                program_name);
               exit(99);
               }

          exit(0);
          };

     if (switch_to_data_fax_mode)
          {

          if (enter_data_fax_mode_wrapper(answer_mode) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not switch to data/fax mode",
                program_name);
               exit(99);
               }

          return(VMA_OK);
          };

     time(&call_start);

     if (cvd.rec_max_len.d.i == 0) {
       lprintf(L_NOISE,
	       "%s: skipping message recording",
	       program_name);
     }
     else if (voice_record_file(message) == FAIL)
          {
          lprintf(L_WARN, "%s: Could not record a message",
           program_name);
          exit(99);
          }

     time(&call_end);
     call_length = call_end - call_start;
     /* 
      * change file owner, group and mode done by function
      */

     if ((cvd.rec_min_len.d.i != 0) && (call_length <= cvd.rec_min_len.d.i))
          switch_to_data_fax_mode = TRUE;

     if ((execute_dtmf_script) && (strlen(cvd.dtmf_program.d.p) != 0))
          {
          char *arguments[3];
          char dtmf_program[VOICE_BUF_LEN];

          arguments[0] = dtmf_code;
          arguments[1] = message;
          arguments[2] = NULL;
          remove_message(message);
          make_path(dtmf_program, cvd.voice_dir.d.p, cvd.dtmf_program.d.p);
          lprintf(L_AUDIT,
           "got DTMF code - executing DTMF program, name='%s', caller=%s, dev=%s, pid=%d",
           CallName, CallerId, DevID, getpid());
          voice_execute_shell_script(dtmf_program, arguments);

#if 0
          if (voice_set_device(NO_DEVICE) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not hang up the line",
                program_name);
               exit(99);
               }
#endif

          if (voice_mode_off() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not turn off voice mode",
                program_name);
               exit(99);
               }

          if (voice_close_device() == FAIL)
               {
               lprintf(L_WARN, "%s: Could not close the voice device",
                program_name);
               exit(99);
               }

          exit(0);
          };

     if (!hangup_requested && (switch_to_data_fax_mode))
          {
          remove_message(message);

          if (enter_data_fax_mode_wrapper(answer_mode) == FAIL)
               {
               lprintf(L_WARN, "%s: Could not switch to data/fax mode",
                program_name);
               exit(99);
               }

          return(VMA_OK);
          };

     if (!hangup_requested)
          {
          if (*beep_sound)
               {
               if (voice_play_file(beep_sound) == FAIL)
                    {
                    lprintf(L_WARN, "%s: Could not play beep sound file",
                     program_name);
                    }
               }
          else
               {
               if (voice_beep(cvd.beep_frequency.d.i, cvd.beep_length.d.i) == FAIL)
                    {
                    lprintf(L_WARN, "%s: Beep command failed");
                    }
               }
          }

     if (voice_set_device(NO_DEVICE) != OK)
          {
          lprintf(L_WARN, "%s: Could not hang up the line",
           program_name);
          exit(99);
          }

     if (voice_mode_off() == FAIL)
          {
          lprintf(L_WARN, "%s: Could not turn off voice mode",
           program_name);
          exit(99);
          }

     if (voice_close_device() == FAIL)
          {
          lprintf(L_WARN, "%s: Could not close the voice device",
           program_name);
          exit(99);
          }

     lprintf(L_AUDIT,
      "message keep, length=%02d:%02d:%02d, name='%s', caller=%s, dev=%s, pid=%d",
      (int) (call_length / 3600), (int) ((call_length / 60) % 60),
      (int) (call_length % 60), CallName, CallerId, DevID, getpid());
     vgetty_create_message_flag_file();

     if (strlen(cvd.message_program.d.p) != 0)
          {
          char *arguments[4];
          char message_program[VOICE_BUF_LEN];

          arguments[0] = message;
          arguments[1] = CallerId;
          arguments[2] = CallName;
          arguments[3] = NULL;
          lprintf(L_NOISE, "executing message program, dev=%s, pid=%d",
           DevID, getpid());
          make_path(message_program, cvd.voice_dir.d.p,
           cvd.message_program.d.p);
          voice_execute_shell_script(message_program, arguments);
          };

     exit(0);
     }
