#! /bin/sh
##
## runtest.sh:						sep '90
##
## Erik Schoenfelder (schoenfr@tubsibr.uucp)
##
##
## run some tests to verify the a60 interpreter.
##
## use: runtest.sh
##

a60='../a60'
tests='fakul.a60 outnum.a60 irnum.a60 outstr.a60 jdev.a60 cbname.a60
	ack.a60 queen.a60 logic1.a60 sin.a60 rmath.a60 goto.a60
	ifstmt.a60 for.a60 procp.a60 sort.a60 iarr.a60
	mama.a60 entier.a60 igral.a60 own.a60 switch.a60 dirty.a60
	syntax.a60'
tmpres='/tmp/rt$$'

if [ `echo -n gna` = "-n gna" ] ; then
        echo='echo'; fin='\c';
else
        echo='echo -n'; fin='done.';
fi

rm -f $tmpres
touch $tmpres

for f in $tests ; do
	$echo "** running $f ... "
	echo "" > $tmpres 2>&1
	echo "$f :" >> $tmpres 2>&1
	echo "" >> $tmpres 2>&1
	$a60 $f >> $tmpres 2>&1
	echo $fin
	echo "checking for differences:"
	diff $tmpres `basename $f .a60`.outp
done

echo ""
echo "ok - thats it."

rm -f $tmpres core

exit 0
