#!/bin/sh

ME=$0

TMPINFILE=/tmp/tw1
TMPOUTFILE=/tmp/tw2
TMPOUTCTRL=/tmp/twctrl
TMPINC1=/tmp/twinc1
TMPINC2=/tmp/twinc2

cat << EOF

=== $ME: DESCRIPTION

    This script excercises the Tripwire preprocessor, testing correctness
variable expansion and include files.

=== $ME: BEGIN ===

EOF
TW="../src/tripwire -E"

cat << EOF > $TMPINFILE
@@define VN1
@@define VN2
@@define VN3
@@define VN4
@@define VN5
@@define V1	Z+pinugs123
@@define V2	Y+pinugs123
@@define V3	Z+pinugs123
@@define V4	W+pinugs123
@@define V5	V+pinugs123
@@VN1
@@VN2
@@VN3
@@VN4
@@VN5
@@V1
@@V2
@@V3
@@V4
@@V5
@@V1 @@V1 @@V1 @@V1 @@V1
@@V1@@V1@@V1@@V1@@V1
@@V1@@V1@@V1@@V1@@V1@@V1@@V1@@V1@@V1@@V1
@@define X1_1	XX
@@{X1_1}
X1_1
@@define X 1
@@define XX 2
@@define XXX 3
@@{X}@@{XX}@@{XXX}
@@include $TMPINC1
EOF

cat << EOF > $TMPOUTCTRL





Z+pinugs123
Y+pinugs123
Z+pinugs123
W+pinugs123
V+pinugs123
Z+pinugs123 Z+pinugs123 Z+pinugs123 Z+pinugs123 Z+pinugs123
Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123
Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123Z+pinugs123
XX
X1_1
123
xxx xxx
xxx xxx
EOF

cat > $TMPINC1 << EOF
@@define F1 xxx
@@{F1} @@F1
@@include $TMPINC2
EOF

cat > $TMPINC2 << EOF
@@{F1} @@F1
EOF

$TW -c $TMPINFILE > $TMPOUTFILE
diff  $TMPOUTFILE $TMPOUTCTRL

if [ $? -ne 0 ] 
then 
	echo "=== $ME: FAILED ==="
	exit 1
else
	echo "=== $ME: PASS ==="
	exit 0
fi

#rm -f $TMPOUTFILE $TMPINFILE $TMPOUTCTRL

