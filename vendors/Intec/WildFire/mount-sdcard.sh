#!/bin/sh

# Usage: mount-sdcard.sh <dir>
#
# Examines each of the /dev/sd? devices/partitions which exist
# for one which has the appropriate signature.
# When found, it is mounted on <dir>
#
# See prep-sdcard.sh for writing the signature.
#
# Needs to be run as root
for dev in /dev/sd*; do
	label=`e2label $dev 2>/dev/null` || continue
	[ -n "$label" ] || continue
	if [ "$label" = "wfsdcard" ]; then
		echo "Found label: $dev=$label"
		break
	else
		echo "Skipping $dev ($label)"
		label=
	fi
done

if [ -z "$label" ]; then
	echo 1>&2 "No partition found with label 'wfsdcard'. Use prep-sdcard.sh"
	exit 1
fi

echo "Erasing $dev"
echo y | /sbin/mkfs.ext3 -j -L wfsdcard $dev
echo "Mounting $dev on $1"
mount -t ext3 $dev $1
