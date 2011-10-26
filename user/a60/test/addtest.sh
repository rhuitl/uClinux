#! /bin/sh
##
## addtest.sh:						oct '90
##
## Erik Schoenfelder (schoenfr@tubsibr.uucp)
##
## use: addtest.sh <name.a60>
## 	to add the new test.
##

a60='../a60'

if [ $# = 0 ] ; then
	echo "use: addtest.sh <file.a60>"
	echo "     to add the example"
	exit 0;
fi

fname=$1
name=`basename $fname .a60`

echo "making output :"
makeoutp.sh $fname > $name.outp

echo "adding to runtest.bat :"
echo "	..\\a60 $fname" >> runtest.bat

echo "adding to runtest.ex :"
echo "" >> runtest.ex
echo "	echo $fname" >> runtest.ex
echo "	/a60 $fname" >> runtest.ex

echo "adding to runtest.g :"
echo "" >> runtest.g
echo "	echo $fname :" >> runtest.g
echo "	..\\a60 $fname" >> runtest.g

exit 0
