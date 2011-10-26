#! /usr/local/bin/vm shell

#
# This is a demo script for the new event handling interface between
# shell scripts and the voice library.
#
# $Id: events.sh,v 1.4 1998/09/09 21:08:01 gert Exp $
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
# Set the device to the dialup line
#

send "DEVICE DIALUP_LINE"

#
# Let's see if it worked
#

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     echo "$0: could not set output device" >&2
     exit 1
fi

#
# Enable events
#

send "ENABLE EVENTS"

#
# Let's see if it worked
#

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     echo "$0: could not enable events" >&2
     exit 1
fi

#
# Let's wait for one hour
#

send "WAIT 3600"

#
# Let's see if it worked
#

ANSWER=`receive`

if [ "$ANSWER" != "WAITING" ]; then
     echo "$0: could not start waiting" >&2
     exit 1
fi

#
# Let's start an infinite loop
#

echo "Waiting for voice events..."

while /bin/true
do
     #
     # Let's wait for events
     #

     ANSWER=`receive`

     #
     # And print, what we got
     #

     echo "$ANSWER"

     #
     # Let's exit upon a 0
     #

     if [ "$ANSWER" = "0" ]; then
          break
     fi

done

echo "Exiting..."

#
# Let's stop waiting
#

send "STOP"

#
# Let's see if it works
#

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     echo "$0: could not stop waiting" >&2
     exit 1
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
