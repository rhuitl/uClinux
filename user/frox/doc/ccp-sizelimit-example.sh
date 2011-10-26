#!/bin/bash
#
# This is a demonstration CCP script for frox. It allows all commands
# as normal except for file downloads. These are permitted only for
# files less than MAXSIZE bytes.
#
# Basically if we read an "I" it is followed by session initialisation
# data, a "C" and it is followed by a message from the client, and an
# "S" and it is followed by a message from the server.
#
# If we write an "X" frox will forward on the message it just sent
# us. Anything else and we are responsible for doing it ourselves. If
# we write "S ..." we send a message to the server, and "C ....." a
# message to the client. "L ......" sends a log message, and should be
# followed by an action. "Q" tells frox to exit this session.
#
# We can't use "C" or "S" to reply to an "I", but we can reply with 
# "R ......." where the R is followed by an IP address. Frox will redirect
# the session to this IP.

MAXSIZE=8192

while read CHAR CMD ARG ; do
  case "$CHAR" in
    I)   # Initialisation message -- leave alone
	echo "X"
	;;
    S)   # Message from server -- leave alone
	echo "X"
	;;
    C)   # Message from client.
        case "$CMD" in
	    RETR)
		echo "S SIZE $ARG"  # Request file size from server
		read CHAR CODE MSG  
		if [ $CODE -gt 299 ] ; then   # Size command failed
		    echo "C 501 Unable to get size of file"
		else
		    if [ $MSG -gt $MAXSIZE ] ; then  # too big
			echo "C 501 File is too large"
		    else
			echo "S $CMD $ARG"  # Forward on request
		    fi
		fi
		;;
	     *)  # Leave other commands alone
		echo "X"
		;;
	esac
	;;
  esac
done

echo "L CCP is Exiting"

