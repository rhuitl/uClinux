# Bash version of Vgetty.pm
#
# Copyright (c)  1999  John Wehle <john@feith.com>.  All rights reserved.
# This package is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.
#
# Derived from:
# 
# $Id: Vgetty.sh,v 1.1 2000/06/11 16:01:44 marcs Exp $
#
# Copyright (c) 1998 Jan "Yenya" Kasprzak <kas@fi.muni.cz>. All rights
# reserved. This package is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

testing=0
log_file='/var/log/voicelog'

event_names="BONG_TONE|BUSY_TONE|CALL_WAITING|DIAL_TONE|\
	DATA_CALLING_TONE|DATA_OR_FAX_DETECTED|FAX_CALLING_TONE|\
	HANDSET_ON_HOOK|LOOP_BREAK|LOOP_POLARITY_CHANGE|NO_ANSWER|\
	NO_DIAL_TONE|NO_VOICE_ENERGY|RING_DETECTED|RINGBACK_DETECTED|\
	RECEIVED_DTMF|SILENCE_DETECTED|SIT_TONE|TDD_DETECTED|\
	VOICE_DETECTED|UNKNOWN_EVENT"

v_log () {
	case "$testing" in
		0|'') ;;
		*) echo "$*" >>"$log_file"
		   ;;
	esac
}

_received_input=""

# The basic two functions (a low-level interface);
v_receive () {
	local dtmf
	local input
	local var

	while true
	do
		read input <&$VOICE_INPUT
		v_log "received: $input"
		eval "case '$input' in		\
			$event_names) ;;	\
			*) break		\
			   ;;			\
		esac"
		# Handle the event:
		dtmf=''
		case "$input" in
			RECEIVED_DTMF) read dtmf <&"$VOICE_INPUT"
				       v_log "DTMF $dtmf"
				       ;;
		esac
		for var in `set`
		do
			var="${var%%=*}"
			case "$var" in
				EVENT_${input}_*) v_log "Running handler ${var##EVENT_${input}_} for event $input"
						  eval \$$var '"$input"' '"$dtmf"'
						  v_log "Handler ${var##EVENT_${input}_} for event $input finished."
						  ;;
			esac
		done
	done
	_received_input=$input
	return 0
}

v_send () {
	local output

	output="$1"
	echo "$output" >&$VOICE_OUTPUT
	kill -PIPE "$VOICE_PID"
	v_log "v_send: $output"
}

v_expect () {
	local expected
	local received

	v_log "expecting: $*"
	v_receive || return 1
	for expected in "$@"
	do
		if [ "$_received_input" = "$expected" ]
		then
			echo "$_received_input"
			return 0
		fi
	done
	return 1
}

v_waitfor () {
	local string

	string="$1"
	while true
	do
		if v_expect "$string" > /dev/null
		then
			break
		fi
	done
}

v_chat () {
	local cmd
	local receive

	receive=0
	for cmd in "$@"
	do
		receive=$(($receive ^ 1))
		case "$cmd" in
			'') continue
			    ;;
		esac
		case "$receive" in
			1) v_expect "$cmd" > /dev/null || return 1
			   ;;
			*) v_send "$cmd"
			   ;;
		esac
	done
	return 0
}

# Initial chat
v_init () {
	v_chat 'HELLO SHELL' 'HELLO VOICE PROGRAM' 'READY'
}

# Setting the voice device
v_device () {
	local dev

	dev="$1"
	v_log "attempting to set device $dev"
	v_chat '' "DEVICE $dev" 'READY' || return
	DEVICE="$dev"
        v_log "sucessfully set device $dev"
}

v_shutdown () {
	v_chat '' 'GOODBYE' 'GOODBYE SHELL'
}

v_enable_events () {
	v_chat '' 'ENABLE EVENTS' 'READY'
}

v_disable_events () {
	v_chat '' 'DISABLE EVENTS' 'READY'
}

v_beep () {
	local freq
	local len

	freq="$1"
	len="$2"
	v_chat '' "BEEP $freq $len" 'BEEPING'
}

v_dial () {
	local num

	num="$1"
	v_chat '' "DIAL $num" 'DIALING'
}

v_getty () {
	local id

	v_chat '' 'GET TTY' || return 1
	v_receive || return 1
	id="$_received_input"
	v_expect 'READY' > /dev/null || return 1
	echo "$id"
	return 0
}

v_modem_type () {
#	To be implemented in vgetty first.
	return 1
}

v_autostop () {
	local arg

	arg="$1"
	v_chat '' "AUTOSTOP $arg" 'READY'
}

v_play () {
	local file

	file="$1"
	v_chat '' "PLAY $file" 'PLAYING'
}

v_record () {
	local file

	file="$1"
	v_chat '' "RECORD $file" 'RECORDING'
}

v_wait () {
	local sec

	sec="$1"
	v_chat '' "WAIT $sec" 'WAITING'
}

v_stop () {
	v_send 'STOP' # Nechceme READY.
}

v_add_handler () {
	local event
	local func
	local name

	event="$1"
	name="$2"
	func="$3"
	eval "case '$event' in					\
		$event_names) ;;				\
		*) v_log 'v_add_handler: unknown event $event';	\
		   return 1					\
		   ;;						\
	esac"
	eval "EVENT_${event}_${name}"="$func"
	return 0
}

v_del_handler () {
	local event
	local name

	event="$1"
	name="$2"
	eval "case '$event' in					\
		$event_names) ;;				\
		*) v_log 'v_del_handler: unknown event $event';	\
		   return 1					\
		   ;;						\
	esac"
	eval "case \"\${EVENT_${event}_${name}}\" in	\
		'') v_log 'v_del_handler: trying to delete nonexistent handler $name' \
		    ;;					\
		*) unset 'EVENT_${event}_${name}'	\
		   ;;					\
	esac"
	return 0
}

v_play_and_wait () {
	local file

	file="$1"
	v_play "$file"
	v_waitfor 'READY'
}

#####################################################################
# The readnum routine, its private variables and the event handler. #
#####################################################################

_readnum_number=""    # The number itself. Filled in by the event handler.
_readnum_pound=0      # Was the '#' key pressed?
_readnum_recursion=0  # Is the event handler already executing?
_readnum_timeout=10   # The value of the timeout. Filled in by v_readnum.

# Event handler. Just adds key to the $_readnum_number.
_readnum_event () {
	local dtmf
	local input

	input="$1" # Unused. Should be 'RECEIVED_DTMF'.
	dtmf="$2"

	case "$_readnum_pound" in
		1) return
		   ;;
	esac
	case "$dtmf" in
		'#') _readnum_pound=1
		     ;;
		*)   _readnum_number="$_readnum_number$dtmf"
		     ;;
	esac
	case "$_readnum_recursion" in
		0) _readnum_recursion=1
		   v_stop
		   v_waitfor 'READY'
		   case "$_readnum_pound" in
			1) v_log "_readnum_event(): Got #; stopping"
			   v_send "WAIT 0"
			   v_waitfor WAITING
			   return
			   ;;
		   esac
		   v_send "WAIT $_readnum_timeout"
		   v_waitfor WAITING
		   _readnum_recursion=0
		   ;;
	esac
}

v_readnum () {
	local message
	local timeout
	local times

        message="$1"
	timeout="$2"
	times="$3"

	case "$timeout" in
		0|'') timeout=10
		      ;;
	esac
	case "$times" in
		0|'') times=3
		      ;;
	esac

	_readnum_number=""
	_readnum_pound=0
	_readnum_recursion=0
	_readnum_timeout="$timeout"

	# Install the handler.
	v_add_handler 'RECEIVED_DTMF' 'readnum' _readnum_event
	while [ -z "$_readnum_number" -a "$_readnum_pound" -eq 0 ]
	do
		times=$(($times - 1))
		if [ "$times" -eq "-1" ]
		then
			break;
		fi
		v_play_and_wait "$message"
		if [ -n "$_readnum_number" -o "$_readnum_pound" -ne 0 ]
		then
			break
		fi
		v_wait "$_readnum_timeout"
		v_waitfor 'READY'
	done
	v_del_handler 'RECEIVED_DTMF' 'readnum'
	case "$times" in
		-1) return 1
		    ;;
	esac
	echo "$_readnum_number"
	return 0
}

v_log "-----------"
v_log "### Pid $$ opening log"
v_log "----------"
v_init
