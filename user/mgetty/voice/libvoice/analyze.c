/*
 * analyze.c
 *
 * Analyze the string in buffer for the appearance of one of the
 * possibilities given in expected_answers in the form "OK|BUSY".
 * If this fails, try to detect some standard voice modem answers.
 *
 * $Id: analyze.c,v 1.6 2001/05/14 11:24:18 marcs Exp $
 *
 */

#include "../include/voice.h"

typedef struct
     {
     char *answer;
     int value;
     } one_modem_answer;

one_modem_answer modem_answers[] =
     {
     {"BUSY", VMA_BUSY},
     {"CONNECT", VMA_CONNECT},
     {"ERROR", VMA_ERROR},
     {"FAX", VMA_FAX},
     {"+FCON", VMA_FCON},
     {"+FCO", VMA_FCO},
     {"NO ANSWER", VMA_NO_ANSWER},
     {"NO CARRIER", VMA_NO_CARRIER},
     {"NO DIAL TONE", VMA_NO_DIAL_TONE},
     {"NO DIALTONE", VMA_NO_DIAL_TONE},
     {"OK", VMA_OK},
     {"RINGING", VMA_RINGING},
     {"RING1", VMA_RING_1},
     {"RING2", VMA_RING_2},
     {"RING3", VMA_RING_3},
     {"RING4", VMA_RING_4},
     {"RING5", VMA_RING_5},
     {"RING 1", VMA_RING_1},
     {"RING 2", VMA_RING_2},
     {"RING 3", VMA_RING_3},
     {"RING 4", VMA_RING_4},
     {"RING 5", VMA_RING_5},
     {"RING A", VMA_RING_1},
     {"RING B", VMA_RING_2},
     {"RING C", VMA_RING_3},
     {"RING D", VMA_RING_4},
     {"RING E", VMA_RING_5},
     {"RING", VMA_RING},
     {"VCON", VMA_VCON},
     {"#VCON", VMA_VCON},
     {"VOICE", VMA_VCON},
     {"\020", VMA_DLE_SHIELD  }, /* in voice:
				  * events reported by the modem are
				  * dle shielded
				  */
     {"DATE", VMA_DATE },        /* Callerid date */
     {"TIME", VMA_TIME },        /* Callerid time */
     {"NMBR", VMA_NMBR },        /* Callerid number */
     {"MESG", VMA_MESG },        /* Callerid unformatted message */
     {"ERRM", VMA_ERRM },        /* Checksumerror in callerid */
     {"DRON", VMA_DRON },        /* Ring on time*/
     {"DROF", VMA_DROF },        /* Ring off time */
     {"CPON", VMA_CPON },        /* Cadencetone on time */
     {"CPOF", VMA_CPOF },        /* Cadencetone off time */
     {"CWON", VMA_CWON },        /* Callwaitingtone on time */
     {"CWOF", VMA_CWOF },        /* Callwaitingtone off time */
     {"ASTB",VMA_IGNORED},
     {"NDID",VMA_IGNORED},
     {"SITT",VMA_IGNORED},
     {"Z",VMA_IGNORED},          /* Manufacturer specific */
     {NULL, VMA_FAIL}
     };    

int voice_analyze(char *buffer, char *expected_answers, int exact_match)
     {
     int current;
     char *user_answer;
     char *new_user_answer;
     int user_answer_length;

     user_answer = expected_answers;

     if (strlen(buffer) == 0)
          return(VMA_EMPTY);

     for(current = 0; ((user_answer != NULL) && (strlen(user_answer) > 0));
      current++)
          {
          new_user_answer = strstr(user_answer, "|");

          if (new_user_answer == NULL)
               user_answer_length = strlen(user_answer);
          else
               user_answer_length = (int) (new_user_answer - user_answer);

          if (exact_match)
               {

               if (strncmp(buffer, user_answer, user_answer_length) == 0)
                    return(current + VMA_USER);

               }
          else
               {

               if (wildmat(buffer, user_answer, user_answer_length) != 0)
                    return(current + VMA_USER);

               }

          if (new_user_answer == NULL)
               user_answer = NULL;
          else
               user_answer = new_user_answer + 1;

          };

     for(current = 0; modem_answers[current].answer != NULL; current++)

          if (strncmp(buffer, modem_answers[current].answer,
           strlen(modem_answers[current].answer)) == 0)
               return(modem_answers[current].value);

     return(VMA_FAIL);
     }
