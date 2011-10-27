#!/bin/bash
# Build a udev permissions file for all devices that a user may encounter
UDEV_FILE=${ROMFSDIR}/etc/udev/rules.d/50-perms.rules

# Set some default values for group and perm
DEFAULT_GROUP="root"
DEFAULT_PERM="0660"

GROUP=$DEFAULT_GROUP
PERM=$DEFAULT_PERM

if [ ! -d `dirname $UDEV_FILE` ]
	then
		mkdir -p `dirname $UDEV_FILE`
fi

rm -f $UDEV_FILE
# Header
echo "# Device node permissions" >> $UDEV_FILE

for i in $@; 
do
	case "$i" in 
	-group=*) GROUP=`echo $i | cut -f2 -d=`;;
	-mode=*) PERM=`echo $i | cut -f2 -d=`;;
	-reset) GROUP=$DEFAULT_GROUP; PERM=$DEFAULT_PERM;;
	*,*) DEV=`echo $i | sed -e 's/,.*//' -e 's,.*/,,'`; DIR=`echo $i | sed -e 's/,.*//' -e 's,[^/]*$,,'`; echo "KERNEL==\"$DEV\", NAME=\"$DIR%k\", GROUP=\"$GROUP\", MODE=\"$PERM\"" >> $UDEV_FILE;;
	esac;	
done

