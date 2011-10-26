#!/bin/sh
#
# /etc/init.d/conntrackd
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Mon, 06 Nov 2006 18:39:07 +0100
#

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

NAME="conntrackd"
DAEMON=`command -v conntrackd`
CONFIG="/etc/conntrack/conntrackd.conf"
PIDFILE="/var/run/${NAME}.pid"


# Gracefully exit if there is no daemon (debian way of life)
if [ ! -x "${DAEMON}" ]; then
	exit 0
fi

# Check for config file
if [ ! -f /etc/conntrackd/conntrackd.conf ]; then
	echo "Error: There is no config file for $NAME" >&2
	exit 1;
fi

case "$1" in
  start)
        echo -n "Starting $NAME: "
	start-stop-daemon --start --quiet --make-pidfile --pidfile "/var/run/${NAME}.pid" --background --exec "${DAEMON}"  && echo "done." || echo "FAILED!"
	;;
  stop)
        echo -n "Stopping $NAME:"
	start-stop-daemon --stop --quiet --oknodo --pidfile "/var/run/${NAME}.pid" && echo "done." || echo "FAILED!"
	;;

  restart)
	$0 start
	$0 stop
	;;

  *)
	echo "Usage: /etc/init.d/conntrackd {start|stop|restart}"
	exit 1
esac

exit 0
