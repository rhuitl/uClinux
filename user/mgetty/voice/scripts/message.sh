#! /usr/local/bin/vm shell

#
# This script calls the given phone number and plays a message.
#
# $1 - phone number to call
# $2 - filename of the message to play (must be a .rmd file, that
#      can be played on the modem used for dialout)
#
# $Id: message.sh,v 1.5 1999/12/04 15:07:34 marcs Exp $
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
# Check command line options
#

if [ $# -ne 2 ]; then
     echo "usage: $0 <phone_number> <filename>" >&2
     exit 99
fi

#
# Let's see if the voice library is talking to us
#

ANSWER=`receive`

if [ "$ANSWER" != "HELLO SHELL" ]; then
     kill -KILL $$
fi

send "HELLO VOICE PROGRAM"

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     kill -KILL $$
fi

#
# Enable events
#

send "ENABLE EVENTS"

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     kill -KILL $$
fi

#
# Start dialout
#

send "DIAL $1"

ANSWER=`receive`

if [ "$ANSWER" != "DIALING" ]; then
     kill -KILL $$
fi

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     echo "ERROR: $ANSWER, aborting"
     exit 99
fi

#
# Disable events
#

send "DISABLE EVENTS"

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     kill -KILL $$
fi

#
# Now play the message file
#

send "PLAY $2"

ANSWER=`receive`

if [ "$ANSWER" != "PLAYING" ]; then
     kill -KILL $$
fi

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
     kill -KILL $$
fi

#
# Let's say goodbye
#

send "GOODBYE"

ANSWER=`receive`

if [ "$ANSWER" != "GOODBYE SHELL" ]; then
     kill -KILL $$
fi

echo "OK: message sent"
exit 0
