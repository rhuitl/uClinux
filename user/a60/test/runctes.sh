#! /bin/sh
##
## runctes.sh:						sep '90
##
## Erik Schoenfelder (schoenfr@tubsibr.uucp)
##
##
## run some tests to verify the a60 interpreter.
##
## use: runctes.sh
##

a60='../a60'
tests='outnum.a60 irnum.a60 outstr.a60 jdev.a60
	ack.a60 logic1.a60 sin.a60 rmath.a60
	ifstmt.a60 for.a60 sort.a60 iarr.a60
	mama.a60 entier.a60'
merk='own.a60 procp.a60 goto.a60 switch.a60 syntax.a60 igral.a60'
tmpres='ctmp-output'

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
	rm -f a.out
	$a60 -C $f >> $tmpres 2>&1
	if [ -f a.out ] ; then
		a.out >> $tmpres 2>&1
		rm -f a.c a.out
	fi
	echo $fin
	echo "checking for differences:"
	diff -c `basename $f .a60`.outp $tmpres
done

echo ""
echo "ok - thats it."

rm -f $tmpres

exit 0
