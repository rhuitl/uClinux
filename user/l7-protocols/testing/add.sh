#!/bin/bash

if ! dc -e ""; then
	echo you do not have dc, so I cannot add these numbers...
	exit 1
fi

n=0
tot=0

while read n; do
	tot=`dc -e "$n $tot + pop" 2> /dev/null`
done

echo $tot seconds
