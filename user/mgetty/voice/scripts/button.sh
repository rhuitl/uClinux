#! /usr/local/bin/vm shell

#
# This is the button script. It is called by vgetty when
# the button DATA/VOICE code was pressed by the user.
#
# Derived from dtmf.sh by Thomas Ziegler <zie@lte.e-technik.uni-erlangen.de>
#
# $Id: button.sh,v 1.3 1998/09/09 21:07:59 gert Exp $
#

VOICE_DIR=/var/spool/voice

FLAG=$VOICE_DIR/.flag
TIMESTAMP=$VOICE_DIR/.timestamp

MSG_DIR=$VOICE_DIR/messages
NO_NEW_MESSAGES=$MSG_DIR/no_new_messages.rmd


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
          logger -t "button.sh[$$]" "Could not start beeping"
          kill -KILL $$
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          logger -t "button.sh[$$]" "Something went wrong on beeping"
          kill -KILL $$
     fi

     }

#
# Define the function to open the device
#

function open_device
     {
     #
     # Set the device
     #
     send "DEVICE INTERNAL_SPEAKER"

     #
     # Let's see if it worked
     #

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          logger -t "button.sh[$$]" "could not set output device"
          exit 1
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
          logger -t "button.sh[$$]" "Could not start playing"
          kill -KILL $$
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          logger -t "button.sh[$$]" "Something went wrong on playing"
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

          if [ $TIME = yes ]; then
               (touch $LOCK ;\
               $VOICE_DIR/speakdate.sh $i 9600 ZyXEL_1496 2 >$TMP ;\
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
     #scrolloff
     }

#
# Let's see if the voice library is talking to us
#

ANSWER=`receive`

if [ "$ANSWER" != "HELLO SHELL" ]; then
     logger -t "button.sh[$$]" "Voice library not answering"
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
     logger -t "button.sh[$$]" "Initialization failed"
     kill -KILL $$
fi

#
# Open the output device (internal speaker)
#

open_device

#
# Play messages
#

messages

#
# Let's say goodbye
#

send "GOODBYE"

#
# Let's see if the voice library got it
#

ANSWER=`receive`

if [ "$ANSWER" != "GOODBYE SHELL" ]; then
     logger -t "button.sh[$$]" "Could not say goodbye to voice library"
     kill -KILL $$
fi

exit 0
