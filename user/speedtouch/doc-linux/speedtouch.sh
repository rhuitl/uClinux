#!/bin/sh
#
# Script Name : speedtouch
#
# chkconfig:   345 91 35
# authors:      Edouard Gomez <ed.gomez@free.fr>
#               Bruno Bonfils <asyd@debian-fr.org>
# revision:    1.8
# description: This SysV script try to establish a connection with an ISP
#              using an Alcatel SpeedTouch USB and benoit papillault's driver
# usage: Depend on linux distro
#
# Return Values :
#  -1  argument unknown
#   0  success
#   1  kernel module loading failed
#   2  kernel module unloading failed
#   3  microcode file is missing
#   4  modem_run executable missing
#   5  modem_run failed to synchronise adsl line  
#   6  ppp executable missing
#   7  ppp connection failed
#   8  usbdevfs mounting failed
#   9  usbdevfs umounting failed
#  10  modprobe executable missing
#  11  mount  executable missing
#  12  umount executable missing
#  13  ifconfig executable missing
#  14  peer file missing
# 255  script not configured
#
# $Id: speedtouch.sh,v 1.7 2004/02/17 21:45:14 edgomez Exp $

# Includes function def
if [ -f /etc/debian_version ] ; then
  RHSTYLE=0
else
  RHSTYLE=1
fi

if [ $RHSTYLE -ne 0 ] ; then

. /etc/init.d/functions

# Check existence of the network file
[ ! -f /etc/sysconfig/network ] && exit 1

# Include network defs
. /etc/sysconfig/network

else
  NETWORKING="yes"
fi

[ ${NETWORKING} = "no" ] && exit 1


if [ -f /etc/speedtouch.conf ]; then
    . /etc/speedtouch.conf
else
    echo "No config file!"
    exit 255
fi

# VARIABLES
MAX_LOOP=60
USBMODULE=$DEFAULT_USBINTERFACE
VERBOSE=0
DEBUG=0

# Lock files
  # Red Hat & Mandrake
SYSCONF_FILE="/var/lock/subsys/speedtouch"
  # Specific for the Debian
MODEM_RUN_PID=/var/run/modem_run.pid

# Change PATH to be sure to include /usr/local/bin
PATH=$PATH:/usr/local/sbin

#PROG NAMES
MODPROBE=$(which modprobe)
KILL=$(which killall)
PPP=$(which pppd)
MODEM_RUN=$(which modem_run)
MOUNT=$(which mount)
UMOUNT=$(which umount)
IFCONFIG=$(which ifconfig)

# will be deprecated? check for existense of /etc/speedtouch.conf
isconfigured()
{

  if [ $CONFIGURED -eq 0 ] ; then
    myecho_failure
    exit 255
  fi

}

myecho_success()
{

  if [ $RHSTYLE -ne 0 ] ; then
    echo_success
    echo
  else
    echo " done."
  fi

}

myecho_failure()
{

  if [ $RHSTYLE -ne 0 ] ; then
    echo_failure
    echo
  else
    echo " failed."
  fi

}

load_kernel_module()
{

  if [ ! -x $MODPROBE ] ; then
    myecho_failure
    exit 10
  fi

  if [ $DEBUG -ne 0 ] ; then
    echo -n "loading $1, "
  fi
  $MODPROBE -k $1 >/dev/null 2>&1
  RETURNED=$?

  if [ $RETURNED -ne 0 ] ; then
    myecho_failure
    exit 1
  fi

}

unload_kernel_module()
{

  if [ ! -x $MODPROBE ] ; then
    myecho_failure
    exit 10
  fi

  if [ $DEBUG -ne 0 ] ; then
    echo -n "unloading $1, "
  fi
  $MODPROBE -r $1 >/dev/null 2>&1
  RETURNED=$?

  if [ $RETURNED -ne 0 ] ; then
    myecho_failure
    exit 2
  fi

}

kill_process()
{

  ps ax | grep -q $1
  RETURNED=$?
  if [ $RETURNED -eq 0 ] ; then
    $KILL $1 >/dev/null 2>&1
  fi

}

connect_adsl_line()
{

  #Launch the modem_run driver
  if [ ! -f $MICROCODE ] ; then
    myecho_failure
    exit 3
  fi

  if [ ! -x $MODEM_RUN ] ; then
    myecho_failure
    exit 4
  fi

  if [ $DEBUG -ne 0 ] ; then
    echo -n "loading firmware, "
  fi
  $MODEM_RUN $MODEM_RUN_OPTIONS -v $VERBOSE -m -f $MICROCODE
  
  RETURNED=$?

  if [ $RETURNED -ne 0 ] ; then
    myecho_failure
    exit 5
  fi

}

connect_ppp()
{

  #Launch ppp daemon
  if [ ! -x $PPP ] ; then
    myecho_failure
    exit 6
  fi

  if [ ! -f "/etc/ppp/peers/$PEER" ] ; then
    myecho_failure
    exit 14
  fi

  if [ ! -x $IFCONFIG ] ; then
    myecho_failure
    exit 13
  fi

  if [ $DEBUG -ne 0 ] ; then
    echo -n "launching ppp session ($PEER), "
  fi
  if [ $RHSTYLE -eq 0 ] ; then
  	start-stop-daemon --start \
		--exec $PPP -- call $PEER >/dev/null 2>&1
  else
  	$PPP call $PEER >/dev/null 2>&1
  fi 
  RETURNED=1
  LOOPS=0

  # Loop until connection has been established with the ISP
  # or the transaction has failed
  while [ $RETURNED -ne 0 ] && [ $LOOPS -le $MAX_LOOP ] ; do
    $IFCONFIG | grep -q 'ppp'
    RETURNED=$?
    LOOPS=`expr $LOOPS + 1`
    sleep 1
  done

  if [ $LOOPS -gt $MAX_LOOP ] && [ $RETURNED -ne 0 ] ; then
    myecho_failure
    exit 7
  fi

}

mount_usb()
{

  if [ ! -x $MOUNT ] ; then
    echo_failure
    exit 11
  fi

  $MOUNT | grep -q usbdevfs
  RETURNED1=$?
  $MOUNT | grep -q usbfs
  RETURNED2=$?

  if [ $RETURNED1 -ne 0 ] && [ $RETURNED2 -ne 0 ] ; then
    if [ $DEBUG -ne 0 ] ; then
      echo -n "mounting usbfs, "
    fi
    $MOUNT none /proc/bus/usb -t usbdevfs

    RETURNED=$?

    if [ $RETURNED -ne 0 ] ; then
      myecho_failure
      exit 8
    fi

  fi

}

umount_usb()
{

  if [ ! -x $MOUNT ] ; then
    echo_failure
    exit 11
  fi

  if [ ! -x $UMOUNT ] ; then
    echo_failure
    exit 12
  fi

  $MOUNT | grep -q usbdevfs
  RETURNED1=$?
  $MOUNT | grep -q usbfs
  RETURNED2=$?

  if [ $RETURNED1 -eq 0 ] || [ $RETURNED2 -eq 0 ] ; then
    if [ $DEBUG -ne 0 ] ; then
      echo -n "unmounting usbfs, "
    fi
    $UMOUNT /proc/bus/usb

    RETURNED=$?

    if [ $RETURNED -ne 0 ] ; then
      myecho_failure
      exit 9
    fi

  fi

}

get_usb_module()
{

  MODULE_CONF="/etc/modules.conf"
  [ -f /etc/conf.modules ] && MODULE_CONF="/etc/conf.modules"
  [ -f /etc/modules.conf ] && MODULE_CONF="/etc/modules.conf"

  USBMODULE=$(grep "usb-interface" ${MODULE_CONF} | awk '{ print $3 }')
  RETURNED=$?
  [ $RETURNED -ne 0 ] || [ "$USBMODULE" = "" ] && USBMODULE=${DEFAULT_USBINTERFACE}
}


###############################################################################
#
#                          Beginning of the script
#
###############################################################################

case "$1" in
    start)
          echo -n "Starting ADSL connection: "
          #isconfigured

          # At least but not at last, Mandrake dependant USB daemon
          [ -x /usr/sbin/usbd ] && usbd -k 1>&2 >/dev/null

          # Load usb core if needed
          if [ $LOAD_USBCORE -ne 0 ] ; then
            load_kernel_module "usbcore"
          fi

          # If one of usb modules has been loaded, mount the usbdevfs
          if [ $LOAD_USBCORE -ne 0 ] || [ $LOAD_USBINTERFACE -ne 0 ] ; then
            mount_usb
            sleep 2
          fi

          # Load usb-interface module described in /etc/modules.conf
          if [ $LOAD_USBCORE -ne 0 ] || [ $LOAD_USBINTERFACE -ne 0 ] ; then
            get_usb_module
            sleep 1
            load_kernel_module "$USBMODULE"
            sleep 3
          fi

          echo $MODEM_RUN_OPTIONS | grep -q -e "-k"
          if [ $? -eq 0 ] ; then
            load_kernel_module "speedtch"
            load_kernel_module "pppoatm"
          fi

          # ADSL synchro
          connect_adsl_line
          sleep 1

          # Load n_hdlc line discipline
          if [ $LOAD_NHDLC -ne 0 ] ; then
            load_kernel_module "n_hdlc"
          fi

          # ISP connection
          connect_ppp

          # Report success
          myecho_success

          if [ $RHSTYLE -ne 0 ] ; then
            touch $SYSCONF_FILE
          fi
          ;;
    stop)
          echo -n "Shutting down ADSL connection: "
          #isconfigured

          # Kill pppd to break ppp connection
          if [ $RHSTYLE -eq 0 ] ; then
	  	start-stop-daemon --stop --pidfile /var/run/ppp0.pid pppd >/dev/null 2>&1
	  	sleep 2
		kill_process modem_run
	  else
	  	kill_process pppd
	  	sleep 2
          	kill_process modem_run
          fi

          echo $MODEM_RUN_OPTIONS | grep -q -e "-k"
          if [ $? -eq 0 ] ; then
            unload_kernel_module "pppoatm"
            unload_kernel_module "speedtch"
          fi

          # Unload HDLC line discipline
          if [ $LOAD_NHDLC -ne 0 ] ; then
            unload_kernel_module "n_hdlc"
          fi

          # At least but not at last, Mandrake dependant USB daemon
          [ -x /usr/sbin/usbd ] && (usbd -k 1>&2 >/dev/null)

          # Unload modules
          if [ $LOAD_USBCORE -ne 0 ] || [ $LOAD_USBINTERFACE -ne 0 ] ; then

            get_usb_module

            unload_kernel_module "$USBMODULE"
            sleep 2

            umount_usb
            sleep 2

            if [ $LOAD_USBCORE -ne 0 ] ; then
              unload_kernel_module "usbcore"
              sleep 1
            fi

          fi

          # Report success
          myecho_success

          # Remove lock file
          if [ $RHSTYLE -ne 0 ] ; then
            rm -f $SYSCONF_FILE
          fi
          ;;
    restart|force-reload)
          echo -n Restarting ADSL connection:
          #isconfigured

          if [ $LOAD_USBCORE -ne 0 ] || [ $LOAD_USBINTERFACE -ne 0 ] ; then

            $0 stop  >/dev/null

            RETURNED=$?

            if [ $RETURNED -ne 0 ] ; then
              myecho_failure
              exit $RETURNED
            fi

            $0 start >/dev/null

            RETURNED=$?

            if [ $RETURNED -ne 0 ] ; then
              myecho_failure
              exit $RETURNED
            fi

          else

            $0 reload >/dev/null

            RETURNED=$?

            if [ $RETURNED -ne 0 ] ; then
              myecho_failure
              exit $RETURNED
            fi

          fi

          myecho_success
          ;;
    reload)
          echo -n Reloading ADSL connection:
          #isconfigured

          # Kills pppd to break ppp connection
          if [ $RHSTYLE -eq 0 ] ; then
	  	start-stop-daemon --stop --pidfile /var/run/ppp0.pid pppd
	  else
	  	kill_process pppd
          fi

          sleep 2
          connect_ppp

          myecho_success
          ;;
    status)
          exit 0
          ;;
    *)
          if [ $RHSTYLE -ne 0 ] ; then
            echo "Usage : $0 [start|stop|restart|reload|status]"
          else
            echo "Usage : $0 {start|stop|restart|force-reload}"
          fi
          exit -1

esac

exit 0
