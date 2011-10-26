#! /bin/sh
##
## runexamp.sh:						dec '90
##
## Erik Schoenfelder (schoenfr@tubsibr.uucp)
##
##
## run the examples one after another...
##
## use: runexamp.sh
##

a60='../a60'
tests='321.a60 prim.a60 rand.a60 serp.a60 teul1.a60 teul2.a60
	whetstone.a60'
tmpres='/tmp/re$$'

rm -f $tmpres
touch $tmpres

for f in $tests ; do
	echo " "
	echo "** running $f ... "
	echo " "
	$a60 $f
	echo " "
	echo "** done ($f)"
	echo " "
done

echo ""
echo "ok - thats it."

rm -f $tmpres

exit 0
