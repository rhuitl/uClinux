#! /bin/sh
##
## make-errmsgs.sh:					july 1991
## (schoenfr)
##
## Use :  make-errmsgs.sh  <src1> ...
##
## extract the a60_error messages...
## 
## [ ** THIS DOES NOT WORK ** ]
##

tmpf="/tmp/gugu-$$"

for f in $* ; do

	rm -f $tmpf

	cat $f | extrerrm | grep -v -i internal | sort -u > $tmpf

	if [ -s $tmpf ] ; then
		echo ""
		echo "$f":
		echo ""
		cat $tmpf
	fi

done

rm -f $tmpf

exit 0
