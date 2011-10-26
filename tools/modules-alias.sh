#!/bin/sh
#
# quick and dirty generation of a modules.alias file for 2.6 kernels
# david_mccullough@securecomputing.com

alias_file="$1"
modinfo="`which modinfo`"
[ -z "$modinfo" ] && modinfo="`which /sbin/modinfo`"

if [ -z "$alias_file" ]
then
	echo "usage: $0 <alias-file>" >&2
	echo "reads module files names on stdin, puts aliases into alias-file" >&2
	exit 1
fi

if [ -z "$modinfo" ]
then
	echo "You need modinfo installed for create modules.alias" >&2
	exit 1
fi

while read module
do
	realname="`basename $module | sed -e 's/\.[k]o$//'`"
	$modinfo $module | grep "alias: " | sed -e 's/alias:[ 	]*//' | while read t
	do
		echo "alias $t $realname"
	done
done > $alias_file

exit 0
