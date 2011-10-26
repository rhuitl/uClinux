/*
 * IS_101.c
 *
 * This file contains generic hardware driver functions for modems that
 * follow the IS-101 interim standard for voice modems. Since the commands
 * are set in the modem structure, it should be quite generic.
 *
 * $Id: IS_101.c,v 1.17 2005/03/13 17:27:45 gert Exp $
 *
 */

#include "../include/voice.h"

/*
 * Here we save the current mode of operation of the voice modem when
 * switching to voice mode, so that we can restore it afterwards.
 */

static char mode_save[16] = "";

/*
 * Internal status variables for stoping voice modem actions.
 */

static int stop_dialing;
static int stop_playing;
static int stop_recording;
static int stop_waiting;

int IS_101_answer_phone(void)
     {

     if ((voice_command(voice_modem->pick_phone_cmnd,
      voice_modem->pick_phone_answr) & VMA_USER) != VMA_USER)
          return(VMA_ERROR);

     return(VMA_OK);
     }

int IS_101_beep(int frequency, int length)
     {
     char buffer[VOICE_BUF_LEN];
     int true_length = length / voice_modem->beep_timeunit;

     reset_watchdog();
     sprintf(buffer, voice_modem->beep_cmnd, frequency, true_length);

     if (voice_command(buffer, "") != OK)
          return(FAIL);

     delay(((length - 1000) > 0) ? (length - 1000) : 0);

     if ((voice_command("", voice_modem->beep_answr) & VMA_USER) != VMA_USER)
          return(FAIL);

     return(OK);
     }

int IS_101_dial(char *number)
     {
     char command[VOICE_BUF_LEN];
     char buffer[VOICE_BUF_LEN];
     time_t timeout;
     int result = FAIL;
     int watchdog_count = 0;

     voice_check_events();
     voice_modem_state = DIALING;
     stop_dialing = FALSE;
     reset_watchdog();
     timeout = time(NULL) + cvd.dial_timeout.d.i;
     sprintf(command, "ATD%s", (char*) number);

     if (voice_write(command) != OK)
          return(FAIL);

     /*
      * Hack to read the ATD... echo that is send by the modem
      * without the final CR
      */

     voice_flush(1);

     while ((!stop_dialing) && (timeout >= time(NULL)))
          {

          if ((watchdog_count--) <= 0)
               {
               reset_watchdog();
               watchdog_count = cvd.watchdog_timeout.d.i * 1000 / 
                cvd.poll_interval.d.i / 2;
               }

          if (check_for_input(voice_fd))
               {

               if (voice_read(buffer) != OK)
                    return(FAIL);

               result = voice_analyze(buffer, command, TRUE);

               switch (result)
                    {
                    case VMA_BUSY:
                         stop_dialing = TRUE;
                         result = OK;
                         queue_event(create_event(BUSY_TONE));
                         break;
                    case VMA_EMPTY:
                         break;
                    case VMA_NO_ANSWER:
                         stop_dialing = TRUE;
                         result = OK;
                         queue_event(create_event(NO_ANSWER));
                         break;
                    case VMA_NO_DIAL_TONE:
                         stop_dialing = TRUE;
                         result = OK;
                         queue_event(create_event(NO_DIAL_TONE));
                         break;
                    case VMA_RINGING:
                    case VMA_USER_1:
                         break;
                    case VMA_OK:
                    case VMA_VCON:
                         stop_dialing = TRUE;
                         result = OK;
                         break;
                    default:
                         stop_dialing = TRUE;
                         result = FAIL;
                         break;
                    };

               }
          else
               delay(cvd.poll_interval.d.i);

          voice_check_events();
          }

     voice_modem_state = IDLE;
     return(result);
     }

int IS_101_handle_dle(char data)
     {
     static int dtmf_shielding = 0;	/* flag variable for shielded DTMF */
     static int dtmf_count = 0;		/* flag variable for shielded DTMF */

     switch (data)
          {

          /*
           * shielded <DLE> code
           */

          case DLE:
               lprintf(L_WARN, "%s: Shielded <DLE> received", program_name);
               return(OK);

          /*
           * shielded <DLE> <DLE> code
           */

          case SUB:
               lprintf(L_WARN, "%s: Shielded <DLE> <DLE> received",
                program_name);
               return(OK);

          /*
           * <ETX> code
           */

          case ETX:
               lprintf(L_WARN, "%s: <DLE> <ETX> received", program_name);
               return(OK);

          /*
           * Bong tone detected
           */

          case '$':
               return(queue_event(create_event(BONG_TONE)));

          /*
           * Start of DTMF shielding
           */

          case '/':
               lprintf(L_NOISE, "%s: Start of DTMF shielding received",
                       program_name);
               dtmf_shielding = 1;
	       dtmf_count = 0;
               return(OK);

          /*
           * End of DTMF shielding
           */

          case '~':
               lprintf(L_NOISE, "%s: End of DTMF shielding received",
                       program_name);
               dtmf_shielding = 0;
               return(OK);

          /*
           * DTMF tone detected
           */

          case '0':
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '6':
          case '7':
          case '8':
          case '9':
          case '*':
          case '#':
          case 'A':
          case 'B':
          case 'C':
          case 'D':
               /* IS-101 DTMF sequence: <DLE></><DLE><value>...<DLE><~>
                *     <DLE><value> is repeated every 70 ms during tone
		* -> use hearing_dtmf flag to generate only one event
		*/
	       dtmf_count++;
               if ( !dtmf_shielding || dtmf_count <= 1 ) 
	       {
                    event_type *event;
                    event_data dtmf;

                    event = create_event(RECEIVED_DTMF);
                    dtmf.c = data;
                    event->data = dtmf;
                    queue_event(event);
	       }
               return(OK);

          /*
           * Data or fax answer detected
           */

          case 'a':
               return(queue_event(create_event(DATA_OR_FAX_DETECTED)));

          /*
           * Busy tone detected
           */

          case 'b':
          case 'K':
               return(queue_event(create_event(BUSY_TONE)));

          /*
           * Fax calling tone detected
           */

          case 'c':
          case 'm':
               return(queue_event(create_event(FAX_CALLING_TONE)));

          /*
           * Dial tone detected
           */

          case 'd':
          case 'i':
               return(queue_event(create_event(DIAL_TONE)));

          /*
           * Data calling tone detected
           */

          case 'e':
          case 'f':
               return(queue_event(create_event(DATA_CALLING_TONE)));

          /*
           * Invalid voice format detected
           */

          case 'E':
               lprintf(L_WARN, "%s: Invalid voice format detected",
                program_name);
               return(OK);

          /*
           * Local handset goes on hook
           */

          case 'h':
          case 'p':
               return(queue_event(create_event(HANDSET_ON_HOOK)));

          /*
           * Local handset goes off hook
           */

          case 'H':
          case 'P':
               return(queue_event(create_event(HANDSET_OFF_HOOK)));

          /*
           * Loop current break
           */

          case 'l':
               return(queue_event(create_event(LOOP_BREAK)));

          /*
           * SIT tone detected
           */

          case 'J':
               return(queue_event(create_event(SIT_TONE)));

          /*
           * Loop current polarity reversal
           */

          case 'L':
               return(queue_event(create_event(LOOP_POLARITY_CHANGE)));

          /*
           * Buffer overrun
           */

          case 'o':
               lprintf(L_WARN, "%s: Buffer overrun", program_name);
               return(OK);

          /*
           * Modem detected silence
           */

          case 'q':
               return(queue_event(create_event(SILENCE_DETECTED)));

          /*
           * XON received
           */

          case 'Q':
               lprintf(L_WARN, "%s: XON received", program_name);
               return(OK);

          /*
           * Ringback detected
           */

          case 'r':
               return(queue_event(create_event(RINGBACK_DETECTED)));

          /*
           * Ring detected
           */

          case 'R':
               return(queue_event(create_event(RING_DETECTED)));

          /*
           * Modem could not detect voice energy on the line
           */

          case 's':
               return(queue_event(create_event(NO_VOICE_ENERGY)));

          /*
           * XOFF received
           */

          case 'S':
               lprintf(L_WARN, "%s: XOFF received", program_name);
               return(OK);

          /*
           * TDD detected
           */

          case 't':
               return(queue_event(create_event(TDD_DETECTED)));

          /*
           * Timing mark will be ignored
           */

          case 'T':
               return(OK);

          /*
           * Buffer underrun
           */

          case 'u':
               lprintf(L_WARN, "%s: Buffer underrun", program_name);
               return(OK);

          /*
           * Voice detected
           */

          case 'v':
          case 'V':
               return(queue_event(create_event(VOICE_DETECTED)));

          /*
           * Call waiting, beep interrupt
           */

          case 'w':
               return(queue_event(create_event(CALL_WAITING)));

          /*
           * Lost data detected event
           */

          case 'Y':
               lprintf(L_WARN, "%s: Lost data detected event", program_name);
               return(OK);

          };

     /*
      * Unknown DLE code
      */

     lprintf(L_WARN, "%s: Unknown code <DLE> <%c>", program_name, data);
     return(FAIL);
     }

int IS_101_init(void)
     {
     LPRINTF(L_WARN, "%s: init called", POS);
     return(FAIL);
     }

int IS_101_message_light_off(void)
     {

     if (voice_command("ATS0=0", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

int IS_101_message_light_on(void)
     {

     if (voice_command("ATS0=254", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

int IS_101_start_play_file(void)
     {
     TIO tio;

     reset_watchdog();
     stop_playing = FALSE;
     voice_modem_state = PLAYING;
     voice_check_events();
     tio_get(voice_fd, &tio);

     if (cvd.do_hard_flow.d.i)
          {

          if ((voice_command(voice_modem->hardflow_cmnd,
           voice_modem->hardflow_answr) & VMA_USER) != VMA_USER)
               return(FAIL);

          tio_set_flow_control(voice_fd, &tio, FLOW_HARD | FLOW_XON_OUT);
          }
     else
          {

          if ((voice_command(voice_modem->softflow_cmnd,
           voice_modem->softflow_answr) & VMA_USER) != VMA_USER)
               return(FAIL);

          tio_set_flow_control(voice_fd, &tio, FLOW_XON_OUT);
          };

     tio_set(voice_fd, &tio);

     if ((voice_command(voice_modem->start_play_cmnd,
      voice_modem->start_play_answr) & VMA_USER) != VMA_USER)
          return(FAIL);

     return(OK);
     }

int IS_101_reset_play_file(void)
     {

     if (voice_write_raw(voice_modem->reset_play_cmnd, strlen(
      voice_modem->reset_play_cmnd)) != OK)
          return(FAIL);

     lprintf(L_JUNK, "%s: <RESET PLAY>", program_name);
     return(OK);
     }

int IS_101_stop_play_file(void)
     {

     if (stop_playing)
          {
          tio_flush_queue(voice_fd, TIO_Q_OUT);

          if( voice_shell_linger > 0 )
               voice_wait( voice_shell_linger );

          if (voice_write_char(0x00) != OK)
               return(FAIL);

          if (voice_write_raw(voice_modem->intr_play_cmnd, strlen(
           voice_modem->intr_play_cmnd)) != OK)
               return(FAIL);

          lprintf(L_JUNK, "%s: <INTERRUPT PLAY>", program_name);

          if ((voice_command("", voice_modem->intr_play_answr) & VMA_USER) !=
           VMA_USER)
               return(FAIL);
          }
     else
          {

          if( voice_shell_linger > 0 )
               voice_wait( voice_shell_linger );

          if (voice_write_raw(voice_modem->stop_play_cmnd, strlen(
           voice_modem->stop_play_cmnd)) != OK)
               return(FAIL);

          lprintf(L_JUNK, "%s: <STOP PLAY>", program_name);

          if ((voice_command("", voice_modem->stop_play_answr) & VMA_USER) !=
           VMA_USER)
               return(FAIL);
          }

     tio_set(voice_fd, &voice_tio);
     voice_check_events();
     voice_modem_state = IDLE;
     return(OK);
     }

int IS_101_play_file(FILE *fd, int bps)
     {
     #define PLAY_BUFFER_SIZE 1023
     static char output_buffer[PLAY_BUFFER_SIZE + 1];
     int bytes_out;
     int bytes_max = bps / 8 / 10;
     int count = 0;
     int play_complete = FALSE;
     time_t watchdog_reset;

     watchdog_reset = time(NULL) + (cvd.watchdog_timeout.d.i / 2);

     if (bytes_max > PLAY_BUFFER_SIZE)
          bytes_max = PLAY_BUFFER_SIZE;

     while ((!stop_playing) && (!play_complete))
          {
          static int modem_byte;
          static int data_byte;

          bytes_out = 0;

          while (bytes_out < bytes_max)
               {

               if ((data_byte = fgetc(fd)) == EOF)
                    {
                    play_complete = TRUE;
                    break;
                    }

               output_buffer[bytes_out] = data_byte;

               if (output_buffer[bytes_out++] == DLE)
                    output_buffer[bytes_out++] = DLE;

               };

          if (voice_write_raw(output_buffer, bytes_out) != OK)
               return(FAIL);

          count += bytes_out;

          if (watchdog_reset < time(NULL))
               {
               lprintf(L_JUNK, "%s: <VOICE DATA %d bytes>", program_name, count);
               reset_watchdog();
               watchdog_reset = time(NULL) + (cvd.watchdog_timeout.d.i / 2);
               count = 0;
               }

          while ((modem_byte = voice_read_byte()) >= 0)
               {

               if (modem_byte == DLE)
                    {

                    if ((modem_byte = voice_read_byte()) < 0)
                         return(FAIL);

                    lprintf(L_JUNK, "%s: <DLE> <%c>", voice_modem_name,
                     modem_byte);
                    voice_modem->handle_dle(modem_byte);
                    }
               else
                    lprintf(L_WARN, "%s: unexpected byte %c from voice modem",
                     program_name, modem_byte);

               };

          voice_check_events();
          };

     if (count > 0)
          {
          lprintf(L_JUNK, "%s: <VOICE DATA %d bytes>", program_name, count);
          reset_watchdog();
          }

     return(OK);
     }

int IS_101_record_file(FILE *fd, int bps)
     {
     TIO tio;
     time_t timeout;
     int input_byte;
     int got_DLE_ETX = FALSE;
     int was_DLE = FALSE;
     int tcount = 0;
     int count = 0;
     time_t watchdog_reset;

     watchdog_reset = time(NULL) + (cvd.watchdog_timeout.d.i / 2);

     reset_watchdog();
     timeout = time(NULL) + cvd.rec_max_len.d.i;
     stop_recording = FALSE;
     voice_modem_state = RECORDING;
     voice_check_events();
     tio_get(voice_fd, &tio);

     if (cvd.do_hard_flow.d.i)
          {

          if ((voice_command(voice_modem->hardflow_cmnd,
           voice_modem->hardflow_answr) & VMA_USER) != VMA_USER)
               return(FAIL);

          tio_set_flow_control(voice_fd, &tio, FLOW_HARD | FLOW_XON_IN);
          }
     else
          {

          if ((voice_command(voice_modem->softflow_cmnd,
           voice_modem->softflow_answr) & VMA_USER) != VMA_USER)
               return(FAIL);

          tio_set_flow_control(voice_fd, &tio, FLOW_XON_IN);
          };

     tio_set(voice_fd, &tio);

     if ((voice_command(voice_modem->start_rec_cmnd,
      voice_modem->start_rec_answr) & VMA_USER) != VMA_USER)
          return(FAIL);

     while (!got_DLE_ETX)
          {
          input_byte = voice_read_byte();

          if ((input_byte < 0) && (input_byte != -EINTR) && (input_byte != -EAGAIN))
               return(FAIL);

          if (input_byte >= 0)
               {

               if (was_DLE)
                    {
                    was_DLE = FALSE;

                    switch (input_byte)
                         {
                         case DLE:
                              fputc(DLE, fd);
                              break;
                         case ETX:
                              got_DLE_ETX = TRUE;
                              lprintf(L_JUNK, "%s: <VOICE DATA %d bytes>",
                               voice_modem_name, count);
                              lprintf(L_JUNK, "%s: <DLE> <ETX>",
                               voice_modem_name);
                              voice_modem->handle_dle(input_byte);
                              break;
                         case SUB:
                              fputc(DLE, fd);
                              fputc(DLE, fd);
                              break;
                         default:
                              lprintf(L_JUNK, "%s: <DLE> <%c>",
                               voice_modem_name, input_byte);
                              voice_modem->handle_dle(input_byte);
                         }

                    }
               else
                    {

                    if (input_byte == DLE)
                         was_DLE = TRUE;
                    else
                         fputc(input_byte, fd);

                    }

               tcount++;

               if (tcount > (bps / 8 / 10))
                    {
                    tcount = 0;

                    if (timeout < time(NULL))
                         voice_stop_recording();

                    }

               count++;

               if (watchdog_reset < time(NULL))
                    {
                    lprintf(L_JUNK, "%s: <VOICE DATA %d bytes>", voice_modem_name,
                     count);
                    reset_watchdog();
                    watchdog_reset = time(NULL) + (cvd.watchdog_timeout.d.i / 2);
                    count = 0;
                    }

               }

          voice_check_events();

          if (input_byte == -EAGAIN)
               delay(cvd.poll_interval.d.i);

          }

     tio_set(voice_fd, &voice_tio);

     if ((voice_command("", voice_modem->stop_rec_answr) & VMA_USER) !=
	 VMA_USER) {
	 return(FAIL);
       }

     voice_check_events();
     voice_modem_state = IDLE;
     return(OK);
     }

int IS_101_set_compression(int *compression, int *speed, int *bits)
     {
     LPRINTF(L_WARN, "%s: set_compression called", POS);
     return(FAIL);
     }

int IS_101_set_device(int device)
     {
     LPRINTF(L_WARN, "%s: set_device called", POS);
     return(FAIL);
     }

int IS_101_stop_dialing(void)
     {
     stop_dialing = TRUE;
     return(OK);
     }

int IS_101_stop_playing(void)
     {
     stop_playing = TRUE;
     return(OK);
     }

int IS_101_stop_recording(void)
     {
     stop_recording = TRUE;

     if (voice_write_raw(voice_modem->stop_rec_cmnd, strlen(
      voice_modem->stop_rec_cmnd)) != OK)
          return(FAIL);

     lprintf(L_JUNK, "%s: <STOP RECORDING>", program_name);
     return(OK);
     }

int IS_101_stop_waiting(void)
     {
     stop_waiting = TRUE;
     return(OK);
     }

int IS_101_switch_to_data_fax(char *mode)
     {
     char buffer[VOICE_BUF_LEN];

     sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd, mode);

     if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
      VMA_USER)
          return(FAIL);

     if (voice_command("AT", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

int IS_101_voice_mode_off(void)
     {
     char buffer[VOICE_BUF_LEN];

     sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd, mode_save);

     if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
      VMA_USER)
          return(FAIL);

     if (voice_command("AT", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

int IS_101_voice_mode_on(void)
     {
     char buffer[VOICE_BUF_LEN];

     if (voice_command(voice_modem->ask_mode_cmnd, "") != OK)
          return(FAIL);

     do
          {

          if (voice_read(mode_save) != OK)
               return(FAIL);

          }
     while (strlen(mode_save) == 0);

     if ((voice_command("", voice_modem->ask_mode_answr) & VMA_USER) !=
      VMA_USER)
          return(FAIL);

     sprintf(buffer, "%s%s", voice_modem->switch_mode_cmnd,
      voice_modem->voice_mode_id);

     if ((voice_command(buffer, voice_modem->switch_mode_answr) & VMA_USER) !=
      VMA_USER)
          return(FAIL);

     if (voice_command("AT", "OK") != VMA_USER_1)
          return(FAIL);

     return(OK);
     }

int IS_101_wait(int wait_timeout)
     {
     time_t timeout;
     int watchdog_count = 0;
     int in_dle = FALSE;

     reset_watchdog();
     stop_waiting = FALSE;
     voice_modem_state = WAITING;
     voice_check_events();
     timeout = time(NULL) + wait_timeout;

     while ((!stop_waiting) && (timeout >= time(NULL)))
          {
          static int char_read;

          if ((watchdog_count--) <= 0)
               {
               reset_watchdog();
               watchdog_count = cvd.watchdog_timeout.d.i * 1000 / 
                cvd.poll_interval.d.i / 2;
               }

          while ((char_read = voice_read_byte()) >= 0) {
             if (in_dle) {
                lprintf(L_JUNK,
                        "%s: <DLE> <%c>",
                        voice_modem_name,
                        char_read);
                voice_modem->handle_dle(char_read);
                in_dle = FALSE;
             }
             else if (char_read == DLE) {
                in_dle = TRUE;
             }
             else {
                  lprintf(L_WARN,
                   "%s: unexpected byte <%c> from voice modem",
                   program_name, char_read);
             }
	  };

          voice_check_events();
          delay(cvd.poll_interval.d.i);
          };

     /* We didn't receive the accompanying byte */
     if (in_dle) {
        lprintf(L_FATAL, "%s: <DLE> not followed by anything", program_name);
        return FAIL;
     }

     voice_check_events();
     voice_modem_state = IDLE;
     return(OK);
     }

int IS_101_play_dtmf(char* number)
     {
     char buffer[VOICE_BUF_LEN], buf2[VOICE_BUF_LEN];
     char *p;

     reset_watchdog();
     sprintf(buffer, voice_modem->play_dtmf_cmd, number[0]);
     for (p = &(number[1]); *p != '\0'; p++) {
            sprintf(buf2, voice_modem->play_dtmf_extra, *p);
            strncat(buffer, buf2, VOICE_BUF_LEN - 1);
     }

     if (voice_command(buffer, "") != OK)
          return(FAIL);

     delay(strlen(number) * 500);

     if ((voice_command("", voice_modem->play_dtmf_answr) & VMA_USER) !=
      VMA_USER)
          return(FAIL);

     return(OK);
     }

int IS_101_check_rmd_adequation(char *rmd_name) {
   return !strncmp(rmd_name,
                   voice_modem_rmd_name,
                   strlen(voice_modem_rmd_name));
}


// juergen.kosel@gmx.de : voice-duplex-patch start
int IS_101_handle_duplex_voice (FILE *tomodem, FILE *frommodem, int bps)
     {
     LPRINTF(L_WARN, "%s: IS_101_handle_duplex_voice called", POS);
     return(FAIL);
     }
// juergen.kosel@gmx.de : voice-duplex-patch end

const char IS_101_pick_phone_cmnd[] = "AT+VLS=2";
const char IS_101_pick_phone_answr[] = "OK";
const char IS_101_beep_cmnd[] = "AT+VTS=[%d,0,%d]";
const char IS_101_beep_answr[] = "OK";
/*         IS_101_beep_timeunit is defined in include/IS_101.h */
const char IS_101_hardflow_cmnd[] = "AT+FLO=2";
const char IS_101_hardflow_answr[] = "OK";
const char IS_101_softflow_cmnd[] = "AT+FLO=1";
const char IS_101_softflow_answr[] = "OK";
const char IS_101_start_play_cmnd[] = "AT+VTX";
const char IS_101_start_play_answer[] = "CONNECT";
const char IS_101_reset_play_cmnd[] = {DLE, FS, 0x00};
const char IS_101_intr_play_cmnd[] = {DLE, CAN, DLE, ETX, 0x00};
const char IS_101_intr_play_answr[] = "OK";
const char IS_101_stop_play_cmnd[] = {DLE, ETX, 0x00};
const char IS_101_stop_play_answr[] = "OK";
const char IS_101_start_rec_cmnd[] = "AT+VRX";
const char IS_101_start_rec_answr[] = "CONNECT";
const char IS_101_stop_rec_cmnd[] = {DLE, '!', 0x00};
const char IS_101_stop_rec_answr[] = "OK";
const char IS_101_switch_mode_cmnd[] = "AT+FCLASS=";
const char IS_101_switch_mode_answr[] = "OK";
const char IS_101_ask_mode_cmnd[] = "AT+FCLASS?";
const char IS_101_ask_mode_answr[] = "OK";
const char IS_101_voice_mode_id[] = "8";
const char IS_101_play_dtmf_cmd[] = "AT+VTS=%c";
const char IS_101_play_dtmf_extra[] = ",%c";
const char IS_101_play_dtmf_answr[] = "OK";

voice_modem_struct IS_101 =
     {
     "IS-101 compatible modem",
     "IS-101",
     (char *) IS_101_pick_phone_cmnd,
     (char *) IS_101_pick_phone_answr,
     (char *) IS_101_beep_cmnd,
     (char *) IS_101_beep_answr,
              IS_101_beep_timeunit,
     (char *) IS_101_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) IS_101_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) IS_101_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) IS_101_intr_play_cmnd,
     (char *) IS_101_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) IS_101_stop_play_answr,
     (char *) IS_101_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) IS_101_stop_rec_cmnd,
     (char *) IS_101_stop_rec_answr,
     (char *) IS_101_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) IS_101_ask_mode_cmnd,
     (char *) IS_101_ask_mode_answr,
     (char *) IS_101_voice_mode_id,
     (char *) IS_101_play_dtmf_cmd,
     (char *) IS_101_play_dtmf_extra,
     (char *) IS_101_play_dtmf_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     NULL,  /* (char *) V253modem_start_duplex_voice_cmnd, */
     NULL,  /* (char *) V253modemstart_duplex_voice_answr, */
     NULL,  /* (char *) V253modem_stop_duplex_voice_cmnd , */
     NULL,  /* (char *) V253modem_stop_duplex_voice_answr, */
     // juergen.kosel@gmx.de : voice-duplex-patch end

     &IS_101_answer_phone,
     &IS_101_beep,
     &IS_101_dial,
     &IS_101_handle_dle,
     &IS_101_init,
     &IS_101_message_light_off,
     &IS_101_message_light_on,
     &IS_101_start_play_file,
     &IS_101_reset_play_file,
     &IS_101_stop_play_file,
     &IS_101_play_file,
     &IS_101_record_file,
     &IS_101_set_compression,
     &IS_101_set_device,
     &IS_101_stop_dialing,
     &IS_101_stop_playing,
     &IS_101_stop_recording,
     &IS_101_stop_waiting,
     &IS_101_switch_to_data_fax,
     &IS_101_voice_mode_off,
     &IS_101_voice_mode_on,
     &IS_101_wait,
     &IS_101_play_dtmf,
     &IS_101_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     &IS_101_handle_duplex_voice,
     NULL, /* since there is no way to enter duplex voice state */
     // juergen.kosel@gmx.de : voice-duplex-patch end
     0
     };
