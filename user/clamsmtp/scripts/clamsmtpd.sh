#!/bin/sh

###########################################################################
# CONFIGURATION

# Most configuration options are found in the clamsmtpd.conf file.
# For more info see:
#   man clamsmtpd.conf

# The prefix clamsmtpd was installed to
prefix=/usr/local/

# The location for pid file
piddir=/var/run/clamav/

###########################################################################
# SCRIPT
            
case $1 in
start)
        mkdir -p $piddir
        $prefix/sbin/clamsmtpd -p $piddir/clamsmtpd.pid
        echo -n "clamsmtpd "
        ;;
stop)
        [ -f $piddir/clamsmtpd.pid ] && kill `cat $piddir/clamsmtpd.pid`
        echo -n "clamsmtpd "
        ;;
*)
        echo "usage: clamsmptd.sh {start|stop}" >&2
        ;;
esac
