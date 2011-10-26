#!/usr/bin/vm shell 
# Robert Jördens <rjo@gmx.de>
#
# This is the dtmf script. It is called by vgetty when a dtmf code was send by
# the user.
#
# $1 - received DTMF code
#
# $2 - name of the recorded voice file or if "-cons_mode", switches on console
# mode so you can enter the dtmf-codes on your console and will hear all sound
# going to your soundcard! (you also have to toogle the magic line at the
# beginning!)
#

if [ "1$2" = "1-cons_mode" ]; then
	CONS_MODE="yes"
else
	CONS_MODE="no"
fi

#
BASENAME=`basename $0`
DTMF="$1"
ALREADY_REC="$2"
# Some dir's
VOICE_DIR=/var/spool/voice
MSG_DIR=$VOICE_DIR/messages
INC_DIR=$VOICE_DIR/incoming
# Some files (scripts may have to be written)
CODE=`cat $VOICE_DIR/.code`
FLAG=$VOICE_DIR/.flag
TIMESTAMP=$VOICE_DIR/.timestamp
CONNECT_SCRIPT=$VOICE_DIR/ppp.sh
FAX_ACTIVATE_SCRIPT=$VOICE_DIR/fax_activate.sh
# Sound-Files
GET_CODE=$MSG_DIR/get-code.rmd
INCORRECT=$MSG_DIR/incorrect.rmd
GOODBYE=$MSG_DIR/goodbye.rmd
NO_NEW_MESSAGES=$MSG_DIR/no_new_messages.rmd
GIMME_COMM=$MSG_DIR/gimme_comm.rmd
OKAY_DRIN=$MSG_DIR/okay_drin.rmd
BYE=$MSG_DIR/bye.rmd
# The TTY's where to toogle the Scroll-LED
LEDTTY=/dev/tty[1-8]
# Tries Code
MAXTRIES=3
# Timeout beetween two equal numbers to be recognized as two single. Under
# TIMEOUT: increment (see dtmf_alph)
TIMEOUT=2
# Type of your Modem
MODEM_TYPE=Rockwell
# Compression
COMPRESSION=4
# Sample Rate needed
SPEED=7200


### BEGIN FUNCTIONS

# Define the function to check for an answer and if it is not the desired it
# will quit!
answer () {
    ANSWER=`receive`
    if [ "$ANSWER" != "$1" ]; then
	logger -t "${BASENAME}[$$]" "Got '$ANSWER', expected '$1'. Harakiri"
       	kill -KILL $$
    fi
}

# Define the function to receive an answer from the voice library
receive () {
  if [ $CONS_MODE = "no" ]; then
     read -r INPUT <&$VOICE_INPUT
  else
     read -r -p "receive: " INPUT
  fi
  echo "$INPUT"
}

# Define the function to send a command to the voice library
send () {
  if [ $CONS_MODE = "no" ]; then
     echo $1 >&$VOICE_OUTPUT
     kill -PIPE $VOICE_PID
  else
     echo "send: $1"
  fi
}

# Define the function send a beep
beep () {
  if [ $CONS_MODE = "no" ]; then
     send "BEEP $1 $2"
     answer "BEEPING"
     answer "READY"
  else
     echo "beep: $1 $2"
  fi
}

# Define the function to play a file
play () {
   if [ $CONS_MODE = "no" ]; then
     send "PLAY $1"
     answer "PLAYING"
     answer "READY"
   else
     rmdtopvf $1 | pvfspeed -s 8000 | pvftobasic > /dev/audio
   fi
     logger -t "${BASENAME}[$$]" "Played $1"
}

# Define the function to play the new messages
messages () {
     if [ ! -f $TIMESTAMP ]; then
          MSGS=`find $INC_DIR/ -type f -name 'v*.rmd' -print`
     else
          MSGS=`find $INC_DIR/ -type f -name 'v*.rmd' -newer $TIMESTAMP -print`
          if [ -z "$MSGS" ]; then
               BASENAME=`basename $TIMESTAMP`
               NEWSTAMP=`find $VOICE_DIR -name $BASENAME -cmin -10 -print`
               if [ "$NEWSTAMP" = "$TIMESTAMP" ]; then
                    MSGS=`find $INC_DIR -type f -name 'v*.rmd' -print`
               fi
          fi
     fi
     touch $TIMESTAMP-n
     if [ -x $VOICE_DIR/speakdate.sh ]; then
          TIME=yes
     else
          TIME=no
     fi
     TMPDIR=${TMPDIR-/tmp}/dtmf.$$
     mkdir -m 0700 $TMPDIR || exit 1
     trap "rm -rf $TMPDIR" 0 1 2 3 7 13 15
     TMP=${TMPDIR}/time.rmd.$$
     LOCK=${TMPDIR}/time-lock.$$
     for i in $MSGS
     do
          if [ $TIME = yes ]; then
               (touch $LOCK ;\
               $VOICE_DIR/speakdate.sh $i $SPEED $MODEM_TYPE $COMPRESSION >$TMP ;\
               rm -f $LOCK) &
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
               rm -f $TMP
          fi
     done
     if [ -z "$MSGS" ]; then
          play "$NO_NEW_MESSAGES"
     fi
     beep 1320 1000
     rm -f $FLAG $TIMESTAMP
     mv $TIMESTAMP-n $TIMESTAMP
#     for tty in $LEDTTY; do
#         setleds -scroll < $tty
#     done
}

# Define the function to read one dtmf code string terminated by #
getcode () {
  if [ $CONS_MODE = "no" ]; then
     RECEIVED=""
     send "ENABLE EVENTS"
     answer "READY"
     send "WAIT 30"
     answer "WAITING"
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
                         logger -t "${BASENAME}[$$]" "Ignoring DTMF $ANSWER"
                    ;;
                    esac
               fi
          else
               if [ "$ANSWER" = "SILENCE_DETECTED" ]; then
                    send "STOP"
               else
                    if [ "$ANSWER" != "READY" ]; then
                         logger -t "${BASENAME}[$$]" "Ignoring $ANSWER"
                    fi
               fi
          fi
     done
     send "DISABLE EVENTS"
     answer "READY"
  else
     read -r -p "Code: " RECEIVED
  fi
     echo "$RECEIVED"
     }

# Get a SMS-like String from DTMF's. The Code-Table is not standard!!
dtmf_alph () {
    TAB_0=(0 + - '#' '*' , '.' : ';' '?' '!' '|' @ / '\\' '$' % £ '~' ¤ ¥ § ¿ ¡)
    TAB_1=(" " '"' "'" "(" ")" "[" "]" "{" "}" "<" ">")
    TAB_2=(a b c 2 ä)
    TAB_3=(d e f 3)
    TAB_4=(g h i 4)
    TAB_5=(j k l 5)
    TAB_6=(m n o 6 ö)
    TAB_7=(p q r s 7 ß)
    TAB_8=(t u v 8 ü)
    TAB_9=(w x y z 9)
    TAB_r=()
    TAB_s=()
    
#    stty cbreak </dev/tty >/dev/tty 2>&1
    
    LAST_TIME=10000000000
    THIS_TIME="0"
    LAST_CHAR=""
    THIS_CHAR=""
    LAST_NUM=""
    THIS_NUM=""
    LIST_CHAR=()
    LIST_NUM=()
    REPT=0
    THIS_TAB=""
    THIS_POS=""
    LAST_POS=""
    ALPH=""
    CHAR=""
    
    while true; do
	THIS_NUM=`getone`
#        THIS_NUM=`perl -e 'print getc(STDIN);'`
#       echo -n "  "
        THIS_TIME=`date +'%s'`
        LIST_NUM=(${LIST_NUM[@]} $THIS_NUM)
        case $THIS_NUM in
        "*")
            if [ "1$LAST_CHAR" != "1" ]; then
                eval $LAST_CHAR=\${TAB_${LAST_NUM}[$REPT]}
            fi
            if [ "$CAPS" = "yes" ]; then
                caps="no"
            else
                caps="yes"
                if [ "1$LAST_CHAR" != "1" ]; then
                    LAST_CHAR=`echo "$LAST_CHAR" | tr "[:lower:]" "[:upper:]"`
                fi
            fi
#           echo -n "made '$LAST_CHAR' caps: '$CAPS'"
            continue
        ;;
        "#")
            LIST_CHAR[$LAST_POS]=$LAST_CHAR
            break
        ;;  
        0|1|2|3|4|5|6|7|8|9)
            if [ "$THIS_NUM" != "$LAST_NUM" -o $(($THIS_TIME - $TIMEOUT)) \
                                                -ge $LAST_TIME ]; then
                LIST_CHAR[$LAST_POS]=$LAST_CHAR
                LAST_NUM=$THIS_NUM
                LAST_POS=$THIS_POS
                THIS_POS=$(($THIS_POS + 1))
                REPT=0
#               echo -n "added '$LAST_CHAR'"
            else
                eval THIS_TAB=(\${TAB_${THIS_NUM}[@]})
                if [ "$REPT" -ge "${#THIS_TAB[@]}" ]; then
                    REPT=0
                else
                    REPT=$(($REPT + 1))
                fi  
#               echo -n "incremented to '$REPT'"
            fi
        ;;  
        *)
#           echo -n "Invalid: '$THIS_CHAR'"
            THIS_NUM=$LAST_NUM
            THIS_CHAR=$LAST_CHAR
            continue
        ;;  
        esac
        eval THIS_CHAR=\${TAB_${THIS_NUM}[$REPT]}
        if [ "$CAPS" = "yes" ]; then
            THIS_CHAR=`echo "$THIS_CHAR" | tr "[:lower:]" "[:upper:]"`
        fi  
        LAST_CHAR=$THIS_CHAR
        LAST_NUM=$THIS_NUM
        LAST_TIME=$THIS_TIME
#       echo "--now: list '${LIST_CHAR[@]}' and LAST_CHAR '$LAST_CHAR'"
    done
    
#    stty -cbreak </dev/tty >/dev/tty 2>&1
#    export LIST_CHAR
    for CHAR in "${LIST_CHAR[@]}"; do
#       echo -n "$CHAR"
        ALPH="$ALPH$CHAR"
    done
    echo "$ALPH"
}   

# exitvm
exitvm () {
  play $GOODBYE
  if [ $CONS_MODE = "no" ]; then
    send "GOODBYE"
    answer "GOODBYE SHELL"
  else
    echo "Bye"
  fi
  exit 0
}

# getone
getone () {
  if [ $CONS_MODE = "no" ]; then
     RECEIVED=""
     send "ENABLE EVENTS"
     answer "READY"
     send "WAIT 30"
     answer "WAITING"
     ANSWER=""
     while [ "$ANSWER" != "READY" ]
     do
          ANSWER=`receive`
          if [ "$ANSWER" = "RECEIVED_DTMF" ]; then
               ANSWER=`receive`
               send "STOP"
               RECEIVED=$ANSWER
          else
               if [ "$ANSWER" = "SILENCE_DETECTED" ]; then
                    send "STOP"
               else
                    if [ "$ANSWER" != "READY" ]; then
                         logger -t "${BASENAME}[$$]" "Ignoring $ANSWER"
                    fi
               fi
          fi
     done
     send "DISABLE EVENTS"
     answer "READY"
  else
     read -r -p "Tone: " RECEIVED
  fi
     echo "$RECEIVED"
     }

# Start the festival Server if necessary
check_fest () {
	if ps ax 2>&1 | grep festival_server | grep -v grep >/dev/null; then
		logger -t "${BASENAME}[$$]" "fesitval_server running"
	else
		nohup festival_server 2>&1 >/dev/null &
		logger -t "${BASENAME}[$$]" "fesitval_server started"
		sleep 5
	fi
}

# Say something
say () {
	check_fest
#	I really want vm­shell to be able to play from a pipe! --async
	if [ "1$1" != "1" ]; then
	   echo "$1" | festival_client --tts_mode fundamental --ttw --otype ulaw | basictopvf | pvfspeed -s $SPEED | pvfamp -A 6 | pvftormd $MODEM_TYPE $COMPRESSION > $MSG_DIR/voice_say.rmd
	else
	   cat - | festival_client --tts_mode fundamental --ttw --otype ulaw | basictopvf | pvfspeed -s $SPEED | pvfamp -A 6 | pvftormd $MODEM_TYPE $COMPRESSION > $MSG_DIR/voice_say.rmd
	fi
	play $MSG_DIR/voice_say.rmd
	rm -f $MSG_DIR/voice_say.rmd
}

# Synthesise some Speech for later playing (to save time)
prep_say () {
	if [ "1$2" == "1" -o ! -s $MSG_DIR/message_${2-prep_say}.rmd ]; then
		check_fest
#		I really want vm­shell to be able to play from a pipe! --async
		echo "$1" | festival_client --tts_mode fundamental --ttw --otype ulaw |	basictopvf | pvfspeed -s $SPEED | pvfamp -A 6 | pvftormd $MODEM_TYPE $COMPRESSION > $MSG_DIR/message_${2-prep_say}.rmd &
		sleep 5
	fi
}

# Play prepared voice
play_say () {
	play $MSG_DIR/message_${1-prep_say}.rmd
#	Don't remove special generated files -- maybe we need 'em later
#	rm -f $MSG_DIR/message_prep_say.rmd
}


### END FUNCTIONS
###  --MAIN--

if [ $CONS_MODE = "no" ]; then
  # Let's see if the voice library is talking to us
  answer "HELLO SHELL"
  # Let's answer the message
  send "HELLO VOICE PROGRAM"
  answer "READY"
  # Let's check the code
fi

TRIES=1
GOT_CORRECT_CODE=no

while [ $TRIES -le $MAXTRIES ]
do
     if [ "$DTMF" = "$CODE" ]; then
          if [ -f $ALREADY_REC ]; then
               rm -f $ALREADY_REC
          fi
          GOT_CORRECT_CODE=yes
          break
     else
          logger -t "${BASENAME}[$$]" "Incorrect DTMF code on try $TRIES"
          beep 1320 100
          play "$INCORRECT"
     fi
     if [ $TRIES -lt $MAXTRIES ]; then
          play "$GET_CODE"
          beep 1320 100
          DTMF=`getcode`
     else
          play "$BYE"
          play "$GOODBYE"
     fi
     TRIES=`expr $TRIES + 1`
done
#
###
### We are in!! Lets give the Menu!
###

if [ "$GOT_CORRECT_CODE" = "yes" ]; then
    prep_say "hash is menu" "help"
    
    prep_say "zeero is command mode. Enter your command with the provided table
    and press hash. Then confirm it with hash. -- One plays your list of
    messages. If there are no new and you ask again it will give you all. --
    Two will connect you to your internet provider in a bout one minute. --
    Three will activate faxgetty for the next 30 minutes. -- Four lets you
    record something from the soundcard and play it. -- Star leaves the menu
    and will hang up the phone." "menu" 

    play "$OKAY_DRIN"
    while true ; do
	play_say "help"
	ANSWER=`getone`
	case "$ANSWER" in
	    "#")
		play_say "menu"
	    ;;
	    0)
		logger -t "${BASENAME}[$$]" "Command mode"
		say "Command mode"
		COMMAND=`dtmf_alph`
		beep 1320 100
		say "Really __ ${COMMAND} __ ?"
		ANSWER=`getone`
		beep 1320 100
		case "$ANSWER" in
		"#")
		    logger -t "${BASENAME}[$$]" "Command '$COMMAND'"
		    su - rj -c "${COMMAND}" 2>&1 | say 
		;;
		*)
		    say "Aborted"
		;;
		esac
	    ;;
	    1)
		logger -t "${BASENAME}[$$]" "Playing messages"
		say "Your list of messages"
		messages
	    ;;
	    2)
		logger -t "${BASENAME}[$$]" "Connecting via PPP"
		say "In a bout 1 minute you will be connected"
		nohup $CONNECT_SCRIPT >/dev/null 2>&1 &
	    ;;
	    3)
		logger -t "${BASENAME}[$$]" "Run faxgetty for the next 30 min"
		say "In a bout 1 minute I will be able to receive faxes"
		nohup $ACTIVATE_FAX >/dev/null 2>&1 &
	    ;;
	    4)
		say "Seconds to receive and amplification?"
		SECS=`getcode`
		beep 1320 100
		AMP=`getcode`
		beep 1320 100
		dd if=/dev/audio bs=8000 count=$SECS | basictopvf | pvfspeed -s $SPEED | pvfamp -A $AMP | pvftormd $MODEM_TYPE $COMPRESSION > $MSG_DIR/abhorch.rmd
		beep 1320 100
		play "$MSG_DIR/abhorch.rmd"
		beep 1320 100
#		rm -f $MSG_DIR/abhorch.rmd
	    ;;
	    "*")
		play $BYE
		beep 1320 100
		exitvm
	    ;;
	esac
    done
fi

###
### All right, that's it, leave!
###

exitvm
