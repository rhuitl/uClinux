#!/bin/sh

if [ -d var_tmpldir ]; then
	echo "remove the var_tmpldir directory first"
	exit 1
fi

# create the var tree locally

mkdir var_tmpldir
mkdir var_tmpldir/tmp
mkdir var_tmpldir/log
mkdir var_tmpldir/run
mkdir var_tmpldir/lock
mkdir var_tmpldir/etc
mkdir var_tmpldir/etc/dhcpc
echo "" > var_tmpldir/etc/resolv.conf

# create the ram filesystem (needs root privilege)

sudo sh ./ramfs.sh var_tmpldir varramfs.img 256

# compress the image

rm -f varramfs.img.gz
gzip varramfs.img

# cleanup

rm -rf var_tmpldir
