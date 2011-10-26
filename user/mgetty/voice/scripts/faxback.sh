#!/bin/sh
#

function receive
     {
     read -r INPUT <&$VOICE_INPUT;
     echo "$INPUT";
     }

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


send "BEEP"
ANSWER=`receive`

if [ "$ANSWER" != "BEEPING" ]; then
  exit 1
fi

ANSWER=`receive`
if [ "$ANSWER" != "READY" ]; then
  exit 1
fi

LOG=/dev/null
send "GETFAX"

ANSWER=`receive`
if [ "$ANSWER" != "HUP_CODE" ]; then
  exit 1
fi
HUP_CODE=`receive`
echo "HUP_CODE=$HUP_CODE" >> $LOG

ANSWER=`receive`
if [ "$ANSWER" != "REMOTE_ID" ]; then
  exit 1
fi
REMOTE_ID=`receive`
echo "REMOTE_ID=$REMOTE_ID" >> $LOG

ANSWER=`receive`
if [ "$ANSWER" = "FAX_FILES" ]; then
  NPAGES=`receive`

  FILES=""
  ANSWER=`receive`
  while [ "$ANSWER" != "READY" ]; do
    FILES="$FILES $ANSWER"
    ANSWER=`receive`
  done

  echo "NPAGES=$NPAGES" >> $LOG
  echo "FILES=$FILES" >> $LOG
fi

if [ "$HUP_CODE" = "0" ]; then
  send "SENDFAX $FILES"
  #
  # eat the rest
  #
  ANSWER=`receive`
  while [ "$ANSWER" != "READY" ]; do
    echo "$ANSWER" >> $LOG
    ANSWER=`receive`
  done
fi

#
# Let's send a final beep
#

send "BEEP"
ANSWER=`receive`

if [ "$ANSWER" != "BEEPING" ]; then
  exit 1
fi

ANSWER=`receive`

if [ "$ANSWER" != "READY" ]; then
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
