#!/bin/sh
# Version of the install script for Lineo's SecureEdge tree.
# We avoid replacing utilities that already exist even if tinylogin has them
# compiled in.  We also force absolutely everything to be placed in /bin
# instead of all over the place.

export LC_ALL=POSIX
export LC_CTYPE=POSIX

prefix=$1
if [ "$prefix" = "" ]; then
    echo "No installation directory, aborting."
    exit 1;
fi
bb_path="$prefix"tinylogin
h=`sort tinylogin.links | uniq`

for i in $h ; do
	app=`basename $i`
	if [ \! -f $prefix$app ]
	then
		echo "  $prefix$app -> $bb_path"
		if [ "$CONFIG_JFFS_FS" = "" ]; then
			ln $bb_path $prefix$app || exit 1
		else
			ln -s tinylogin $prefix$app || exit 1
		fi
	else
		echo "  $prefix$app already exists"
	fi
done

exit 0
