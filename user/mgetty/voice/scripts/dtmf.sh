#! /usr/local/bin/vm shell

#
# This is the dtmf script. It is called by vgetty when a dtmf code was
# send by the user.
#
# $1 - received DTMF code
# $2 - name of the recorded voice file
#
# $Id: dtmf.sh,v 1.4 1998/09/09 21:08:01 gert Exp $
#

VOICE_DIR=/var/spool/voice

CODE=`cat $VOICE_DIR/.code`
FLAG=$VOICE_DIR/.flag
TIMESTAMP=$VOICE_DIR/.timestamp

MSG_DIR=$VOICE_DIR/messages
GET_CODE=$MSG_DIR/get-code.rmd
INCORRECT=$MSG_DIR/incorrect.rmd
GOODBYE=$MSG_DIR/goodbye.rmd
NO_NEW_MESSAGES=$MSG_DIR/no_new_messages.rmd

MAXTRIES=3

#
# Define the function to receive an answer from the voice library
#

function receive
     {
     read -r INPUT <&$VOICE_INPUT;
     echo "$INPUT";
     }

#
# Define the function to send a command to the voice library
#

function send
     {
     echo $1 >&$VOICE_OUTPUT;
     kill -PIPE $VOICE_PID
     }

#
# Define the function send a beep
#

function beep
     {
     send "BEEP $1 $2"
     ANSWER=`receive`

     if [ "$ANSWER" != "BEEPING" ]; then
          logger -t "dtmf.sh[$$]" "Could not start beeping"
          kill -KILL $$
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          logger -t "dtmf.sh[$$]" "Something went wrong on beeping"
          kill -KILL $$
     fi

     }

#
# Define the function to play a file
#

function play
     {
     send "PLAY $1"
     ANSWER=`receive`

     if [ "$ANSWER" != "PLAYING" ]; then
          logger -t "dtmf.sh[$$]" "Could not start playing"
          kill -KILL $$
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          logger -t "dtmf.sh[$$]" "Something went wrong on playing"
          kill -KILL $$
     fi

     }

#
# Define the function to play the new messages
#

function messages
     {

     if [ ! -f $TIMESTAMP ]; then
          MSGS=`find $VOICE_DIR/incoming/ -type f -name 'v*.rmd' -print`
     else
          MSGS=`find $VOICE_DIR/incoming/ -type f -name 'v*.rmd' -newer $TIMESTAMP -print`

          if [ -z "$MSGS" ]; then
               BASENAME=`basename $TIMESTAMP`
               NEWSTAMP=`find $VOICE_DIR -name $BASENAME -cmin -10 -print`

               if [ "$NEWSTAMP" = "$TIMESTAMP" ]; then
                    MSGS=`find $VOICE_DIR/incoming/ -type f -name 'v*.rmd' -print`
               fi

          fi

     fi

     touch $TIMESTAMP-n

     if [ -x $VOICE_DIR/speakdate.sh ]; then
          TIME=yes
     else
          TIME=no
     fi

     TMP=/tmp/time.rmd.$$
     LOCK=/tmp/time-lock.$$

     for i in $MSGS
     do

          #
          # The sample speed, modem type and compression is hardcoded
          # here for the moment. Will be automatically set to correct
          # values in a later version.
          #
          # For ISDN4Linux use:
          # ...speakdate.sh $i 9600 ISDN4Linux 4 >$TMP ;\
          # For Rockwell modems use:
          # ...speakdate.sh $i 7200 Rockwell 4 >$TMP ;\
          # For the ZyXEL Elite 2864 use:
          # ...speakdate.sh $i 9600 ZyXEL_2864 4 >$TMP ;\
          #

          if [ $TIME = yes ]; then
               (touch $LOCK ;\
               $VOICE_DIR/speakdate.sh $i 9600 ZyXEL_1496 4 >$TMP ;\
               rm $LOCK) &
          fi

          beep 1320 100
          play $i
          beep 1320 100

          if [ $TIME = yes ]; then

               while [ -f $LOCK ]
               do
                    sleep 1
               done

               play $TMP
               rm $TMP
          fi

     done

     if [ -z "$MSGS" ]; then
          play "$NO_NEW_MESSAGES"
     fi

     beep 880 1000
     rm -f $FLAG $TIMESTAMP
     mv $TIMESTAMP-n $TIMESTAMP
     #
     # I'm using the scroll lock LED on my keyboard to signal new calls.
     # This program resets this LED. You probably want to disable it.
     #
     scrolloff
     }

#
# Define the function to read one dtmf code string
#

function getcode
     {
     RECEIVED=""
     send "ENABLE EVENTS"

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          logger -t "dtmf.sh[$$]" "Could not enable events"
          kill -KILL $$
     fi

     send "WAIT 30"

     ANSWER=`receive`

     if [ "$ANSWER" != "WAITING" ]; then
          logger -t "dtmf.sh[$$]" "Could not start waiting"
          kill -KILL $$
     fi

     ANSWER=""

     while [ "$ANSWER" != "READY" ]
     do
          ANSWER=`receive`

          if [ "$ANSWER" = "RECEIVED_DTMF" ]; then
               ANSWER=`receive`

               if [ "$ANSWER" = "*" ]; then
                    RECEIVED=""
               else

                    case $ANSWER in
                    "#")
                         send "STOP"
                                  ;;
                    0|1|2|3|4|5|6|7|8|9)
                         RECEIVED=$RECEIVED$ANSWER
                                  ;;
                    *)
                         logger -t "dtmf.sh[$$]" "Ignoring DTMF $ANSWER"
                                  ;;
                    esac

               fi

          else

               if [ "$ANSWER" = "SILENCE_DETECTED" ]; then
                    send "STOP"
               else

                    if [ "$ANSWER" != "READY" ]; then
                         logger -t "dtmf.sh[$$]" "Ignoring $ANSWER"
                    fi

               fi

          fi

     done

     send "DISABLE EVENTS"

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          logger -t "dtmf.sh[$$]" "Could not disable events"
          kill -KILL $$
     fi

     echo "$RECEIVED"
     }

#
# Let's see if the voice library is talking to us
#

ANSWER=`receive`

if [ "$ANSWER" != "HELLO SHELL" ]; then
     logger -t "dtmf.sh[$$]" "Voice library not answering"
     kill -KILL $$
fi

#
# Let's answer the message
#

send "HELLO VOICE PROGRAM"

#
# Let's see if it worked
#

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     logger -t "dtmf.sh[$$]" "Initialization failed"
     kill -KILL $$
fi

#
# Let's check the code
#

TRIES=1
DTMF=$1

while [ $TRIES -le $MAXTRIES ]
do

     if [ "$DTMF" = "$CODE" ]; then

          if [ -f $2 ]; then
               rm -f $2
          fi

          messages
          break
     else
          logger -t "dtmf.sh[$$]" "Incorrect DTMF code on try $TRIES"
          beep 1320 100
          play "$INCORRECT"
     fi

     if [ $TRIES -lt $MAXTRIES ]; then
          play "$GET_CODE"
          beep 1320 100
          DTMF=`getcode`
     else
          play "$GOODBYE"
     fi

     TRIES=`expr $TRIES + 1`
done
#
# Let's say goodbye
#

send "GOODBYE"

#
# Let's see if the voice library got it
#

ANSWER=`receive`

if [ "$ANSWER" != "GOODBYE SHELL" ]; then
     logger -t "dtmf.sh[$$]" "Could not say goodbye to voice library"
     kill -KILL $$
fi

exit 0
