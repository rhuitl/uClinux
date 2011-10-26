#!/bin/sh
#
# From: Sarantos Kapidakis <sarantos@ics.forth.gr>
# To: gert@greenie.muc.de
# Subject: Re: mgetty
#
# By the way, this is my fax-answer-now script (you can include it in
# the distribution as an example, if you want),
# which asks mgetty to answer pick up the phone, and if there is no
# mgetty running (it depends on my init level), it starts a single
# mgetty for answering this one call.
#
#!/bin/sh
sig=-USR1
port=${1:-ttyS1}
if pid=`cat /etc/mg-pid.$port 2>/dev/null` && kill $sig $pid  2>/dev/null
then
	:
else
	/usr/local/sbin/mgetty $port < /dev/null &
	echo "starting mgetty..."
	sleep 4
	pid=`cat /etc/mg-pid.$port`
	kill $sig $pid
fi
echo "sending mgetty, pid $pid, signal $sig..."
