#! /bin/sh

MODULE_DIR=/lib/modules/`uname -r`/kernel

case "$1" in
    mount-unmount)
	trap "umount $3; rm -f $2; rmdir $3" 0
	mkdir $3
	dd bs=1204k count=20 if=/dev/zero of=$2
	mke2fs -F $2
	tune2fs -c 0 $2
	modprobe loop
	while true; do mount -o loop $2 $3; umount $3; sleep 1; done
	;;
    bang-one)
	trap "rmmod $2" 0
	while true; do modprobe $2; rmmod $2; done
	;;
    bang-all)
	while true; do
	    # Randomize order
	    find $MODULE_DIR -name '*.ko' | ( while read mod; do echo $RANDOM $mod; done ) | sort -n |
		while read junk modname; do
  		    if [ $RANDOM -gt $RANDOM ]; then
 			rmmod `basename $modname .ko`
 		    else
 			modprobe `basename $modname .ko`
  		    fi
		done
	done
	;;
    "")
	$0 mount-unmount testfs.$$ /tmp/$$ &
	$0 bang-one ext2 &
	$0 bang-all &
	exit 0
	;;
    *)
	echo Unknown arg "$1"
	exit 1
	;;
esac
