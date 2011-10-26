#!/bin/sh

# ram disk helper script
#
# you need to be root to run this script,
#
# usage: ramfs.sh <ramfsdir> <ramfsimgfile> <ramfssize>
#   ramfsdir     : the directory containing the files/dirs to load into the ram disk
#   ramfsimgfile : the name of the file to be created as ramdisk
#   ramfssize    : the size of the ramdisk in kB, on standard linux distrib, the limit
#                  is usually 4096 (4MB)
#
# ------------------------------------------------------------------
# Example 1: creating a ramdisk from a directory
#
#   sh ramfs.sh ../origdir ramfs.img 2048
#
# Once the ramdisk file has been created, you may use it as follows:
#
#   cat ramfs.img > /dev/ram0
#   mount -t ext2 /dev/ram0 /mountpoint
#   cd /mountpoint; ls
#
# you should see a copy of the ../origdir directory.
#
# ------------------------------------------------------------------
# Example 2: creating an empty ramdisk
#
#   sh ramfs.sh foo ramfs.img 2048
#
# if foo does not refer to an existing directory,
# an empty ramdisk is created
#
# ------------------------------------------------------------------

if [ $# != 3 ]; then
	echo "usage: $0 <ramfsdir> <ramfsimgfile> <ramfssize>"
	exit 1
fi

RAMFSDIR=$1
RAMFSIMG=$2
RAMFSSIZE=$3

RAMFSINSZ=1024
RAMDISK=/dev/ram0
MOUNTP=/mnt

if [ ! -b ${RAMDISK} ]; then
	echo "${RAMDISK} not found: ramdisk support is needed"
	exit 1
fi

if [ ! -d ${MOUNTP} ]; then
	echo "${MOUNTP} not found: a temp mount point is needed"
	exit 1
fi

dd if=/dev/zero of=${RAMDISK} bs=1k count=${RAMFSSIZE}
mke2fs -vm5 -O none -i ${RAMFSINSZ} ${RAMDISK} ${RAMFSSIZE}
tune2fs -i 0 ${RAMDISK}
mount ${RAMDISK} ${MOUNTP}
rmdir ${MOUNTP}/lost+found
if [ -d ${RAMFSDIR} ]; then
	cp -pr ${RAMFSDIR}/* ${MOUNTP}
	(cd ${MOUNTP}; chown -R 0 . ; chgrp -R 0 . )
else
	echo "${RAMFSDIR} not found: creating an empty ram disk"
fi
umount ${MOUNTP}
dd if=${RAMDISK} of=${RAMFSIMG} bs=1k count=${RAMFSSIZE}
