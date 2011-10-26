#!/bin/sh
# Version of the install script for the SnapGear/uClinux tree.
# We avoid replacing utilities that already exist even if busybox has them
# compiled in when creating symbolic links.  There is also a --nosubdir
# option to force absolutely everything to be placed in /bin instead of
# all over the place.

export LC_ALL=POSIX
export LC_CTYPE=POSIX

prefix=$1
if [ "$prefix" = "" ]; then
    echo "No installation directory, aborting."
    exit 1;
fi
shift

hardlinks=0
nosubdir=0
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--hardlinks" ]; then
    	hardlinks=1
    elif [ "$1" = "--nosubdir" ]; then
    	nosubdir=1
	mkdir -p $prefix || exit 1
    else
    	echo "Invalid argument: $1"
    fi
    shift
done
if [ "$hardlinks" = "1" ]; then
    linkopts="-f"
else
    linkopts="-fs"
fi
h=`sort busybox.links | uniq`

for i in $h ; do
    if [ "$nosubdir" = "1" ]; then
	app=`basename $i`
	if [ "$hardlinks" = "1" ]; then
	    bb_path="$prefix"busybox
	else
	    bb_path=busybox
	fi
    else
	app=$i
	appdir=`dirname $i`
	mkdir -p $prefix$appdir || exit 1
	if [ "$hardlinks" = "1" ]; then
	    bb_path="$prefix"bin/busybox
	else
	    case "$appdir" in
		/)
		    bb_path="bin/busybox"
		;;
		/bin)
		    bb_path="busybox"
		;;
		/sbin)
		    bb_path="../bin/busybox"
		;;
		/usr/bin|/usr/sbin)
		    bb_path="../../bin/busybox"
		;;
		*)
		echo "Unknown installation directory: $appdir"
		exit 1
		;;
	    esac
	fi
    fi
    if [ "$hardlinks" = "1" -o ! -f $prefix$app ]; then
	echo "  $prefix$app -> $bb_path"
	ln $linkopts $bb_path $prefix$app || exit 1
    else
	echo "  $prefix$app already exists"
    fi
done

romfs-inst.sh -e CONFIG_USER_BUSYBOX_TELNETD \
	-a "telnet  stream tcp nowait root /bin/telnetd telnetd" /etc/inetd.conf

exit 0
