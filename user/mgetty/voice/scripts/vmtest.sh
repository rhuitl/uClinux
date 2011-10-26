#! /usr/local/bin/vm shell

#
# This is the vmtest script. You can call this script to test voice shell
# commands interactively
#
# $Id: vmtest.sh,v 1.4 1998/09/09 21:08:03 gert Exp $
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
echo "* $ANSWER"

if [ "$ANSWER" != "HELLO SHELL" ]; then
     kill -KILL $$
fi

#
# Let's answer the message
#

send "HELLO VOICE PROGRAM"
echo "HELLO VOICE PROGRAM"

#
# Let's see if it worked
#

ANSWER=`receive`
echo "* $ANSWER"

if [ "$ANSWER" != "READY" ]; then
     kill -KILL $$
fi

(while read -r ANSWER <&$VOICE_INPUT ; do echo "* $ANSWER" ; done) &

COMMAND=""

while [ "$COMMAND" != "GOODBYE" ] ; do
     read -r COMMAND
     send "$COMMAND"
done

sleep 2
exit 0
