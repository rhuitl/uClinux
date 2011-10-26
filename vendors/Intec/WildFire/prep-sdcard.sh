#!/bin/sh

# Usage: prep-sdcard.sh [-1] <device>
#
# Prepares the given sdcard (e.g. /dev/sda) by partitioning
# (unless -1 is specified) and creating an ext3 filesystem with a
# label of 'wfsdcard' so that it will be recognised by mount-sdcard.sh
#
# Needs to be run as root

if [ "X$1" = "X-1" ]; then
	shift
	part=
else
	part=${1}1
fi

if [ ! -e "$1" ]; then
	echo 1>&2 "Usage: prep-sdcard.sh [-1] <device>"
	exit 1
fi

getsize()
{
	size=`sfdisk -s $1 2>/dev/null`
	if [ -n "$size" ]; then
		echo `expr $size / 1000`KB
	else
		echo "???KB"
	fi
}

if [ -n "$part" ]; then
	echo -n "Are you sure you want to partition $1 (`getsize $1`)? (y/n) "
	read X
	if [ "$X" != "y" -a "$X" != "Y" ]; then
		exit 1
	fi
	# Just create a single partition for the whole device
	echo 0 | sfdisk $1 || exit 1
else
	part=$1
fi

echo -n "Are you sure you want to erase $part (`getsize $part`)? (y/n) "
read X
if [ "$X" != "y" -a "$X" != "Y" ]; then
	exit 1
fi
mkfs.ext3 -j -L wfsdcard $part
