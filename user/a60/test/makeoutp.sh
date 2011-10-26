#! /bin/sh
##
## makeoutp.sh:					sep '90
##
## Erik Schoenfelder (schoenfr@tubsibr.uucp)
##
## use: makeoutp.sh <name.a60>
## 	to generate the output for an example
##

if [ -x ../a60 ] ; then
	a60='../a60'
else
	a60=a60
fi


if [ $# = 0 ] ; then
	echo "use: makeoutp.sh <file.a60>"
	echo "     to run an example"
	exit 0;
fi

fname=$1

echo ""
echo `basename $fname` ":"
echo ""
$a60 $fname

exit 0
