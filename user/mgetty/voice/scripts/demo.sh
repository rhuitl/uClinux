#! /usr/local/bin/vm shell

#
# This is a demo script for the new interface between shell scripts and
# the voice library
#
# $Id: demo.sh,v 1.4 1998/09/09 21:08:00 gert Exp $
#

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
# Let's see if the voice library is talking to us
#

ANSWER=`receive`

if [ "$ANSWER" != "HELLO SHELL" ]; then
     echo "$0: voice library not answering" >&2
     exit 1
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
     echo "$0: initialization failed" >&2
     exit 1
fi

#
# Set the device
#

if [ "$1" = "dialup" ]; then
     send "DEVICE DIALUP_LINE"
else
     send "DEVICE INTERNAL_SPEAKER"
fi

#
# Let's see if it worked
#

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     echo "$0: could not set output device" >&2
     exit 1
fi

#
# Let's send demo.rmd if it exists
#

if [ -f demo.rmd ]; then
     send "PLAY demo.rmd"

     #
     # Let's see if it works
     #

     ANSWER=`receive`

     if [ "$ANSWER" != "PLAYING" ]; then
          echo "$0: could not start playing" >&2
          exit 1
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          echo "$0: something went wrong on playing" >&2
          exit 1
     fi

fi

#
# Let's record a new demo.rmd if we are connected to the dialup
# line
#

if [ "$1" = "dialup" ]; then
     #
     # Let's send a beep
     #

     send "BEEP"

     #
     # Let's see if it works
     #

     ANSWER=`receive`

     if [ "$ANSWER" != "BEEPING" ]; then
          echo "$0: could not send a beep" >&2
          exit 1
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          echo "$0: could not send a beep" >&2
          exit 1
     fi

     #
     # Let's start the recording
     #

     send "RECORD demo.rmd"

     #
     # Let's see if it works
     #

     ANSWER=`receive`

     if [ "$ANSWER" != "RECORDING" ]; then
          echo "$0: could not start recording" >&2
          exit 1
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          echo "$0: something went wrong on recording" >&2
          exit 1
     fi

     #
     # Let's send a final beep
     #

     send "BEEP"

     #
     # Let's see if it works
     #

     ANSWER=`receive`

     if [ "$ANSWER" != "BEEPING" ]; then
          echo "$0: could not send a beep" >&2
          exit 1
     fi

     ANSWER=`receive`

     if [ "$ANSWER" != "READY" ]; then
          echo "$0: could not send a beep" >&2
          exit 1
     fi

fi

#
# Let's say goodbye
#

send "GOODBYE"

#
# Let's see if the voice library got it
#

ANSWER=`receive`

if [ "$ANSWER" != "GOODBYE SHELL" ]; then
     echo "$0: could not say goodbye to the voice library" >&2
     exit 1
fi

exit 0
