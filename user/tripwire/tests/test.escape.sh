#!/bin/sh

# $Id: test.escape.sh,v 1.2 1993/12/12 01:39:05 genek Exp $
#
#	Rigorous Tripwire functionality test suite
#
# Gene Kim
# Purdue University
#

ME=$0
TMPDIR=/tmp/twtest
TWCONFIG=$TMPDIR/tw.config
TWDB=$TMPDIR/tw.db
TRIPWIRE="../src/tripwire -loosedir -c $TWCONFIG -d $TWDB -i all "
NEWFILE="$TMPDIR/d1/@@NEWFILE"
OLDFILE="$TMPDIR/@@OLDFILE"
GROWFILE="$TMPDIR/grow"
STATFILE="/tmp/twstat";

SAVETWDB=/tmp/twXXX
LOGFILE=/tmp/TWLOG

STATUSADD=2			# exit status of Tripwire
STATUSDEL=4
STATUSCHA=8

MYRUN=/tmp/twrun.sh
MYCHECK=/tmp/twcheck.sh
MYCREATE=/tmp/twcreate.sh
MYINIT=/tmp/twinit.sh
MYCREATETWCONF=/tmp/twctwconf.sh

cat << GHK
=== $ME: DESCRIPTION

    This is similar to the Tripwire update tests, but escaped
filenames are specifically exercised.

GHK

echo "=== $ME: Setting up auxiliary scripts ==="

# build run()
cat << 'EOF' > $MYRUN
    echo running Tripwire
    echo $*
    $*
    laststatus=$?
    echo $laststatus > $STATFILE
EOF

# build checkstat()
cat << 'EOF' > $MYCHECK
    DESIRED=$1
    laststatus=`cat $STATFILE`
    if [ $laststatus -ne $DESIRED ]
    then
	echo "=== $ME: test FAILED! (expecting $DESIRED, got $laststatus) ==="
	echo "=== ($LOGFILE contains output from test script and Tripwire) ==="
	exit 1
    fi
EOF

####

TMPFILES="@1 @2 @3 @4 @5"
TMPDIRS="d1 d2"


cat << 'EOF' > $MYCREATE
    #echo "=== $ME:    creating test environment ==="

	rm -rf $TMPDIR
	mkdir $TMPDIR
	for f in $TMPFILES; do
	    touch $TMPDIR/$f
	done
	for d in $TMPDIRS; do
	    mkdir $TMPDIR/$d
	    for f in $TMPFILES; do
		touch $TMPDIR/$d/$f
	    done
	done
	touch $OLDFILE
	touch $GROWFILE
EOF

cat << 'EOF' > $MYINIT
    #echo "=== $ME:    initializing the database ==="

	touch $TWCONFIG $TWDB $OLDFILE
	rm -f databases/*
	set _ $TRIPWIRE -initialize -q; shift
	( . $MYRUN ; ) > $LOGFILE 
	set _ 0; shift
	. $MYCHECK

	# move database
	rm -f databases/*.old
	cp databases/tw.db* $TWDB

	# save a copy
	cp ./databases/* $SAVETWDB
EOF

cat << 'EOF' > $MYCREATETWCONF
    #echo "=== $ME:    creating tw.config file ==="

	cat << GHK > $TWCONFIG
#
$TMPDIR		R
$TMPDIR/d1	R
$TMPDIR/d2	R
$TWCONFIG
$TMPDIR/grow	L>
$TWDB	E
#
GHK

EOF

# create the tw.config file
# initialize the database
# test update functionality
#	case i.		updated entry
#	case ii.	updated file
#	case iii.	deleted file
#	case iv.	added file
#

echo === $ME: BEGIN ===
	echo $TRIPWIRE

    . $MYCREATE
    . $MYCREATETWCONF
    . $MYINIT

echo "=== $ME: testing complex UPDATE cases"
echo "=== $ME:  changed ignore-mask (UPDATE file)"
    touch $TMPDIR/d1/@1
    set _ $TRIPWIRE -q ; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSCHA; shift
    . $MYCHECK 

    # change the ignore mask
    sed "s,$TMPDIR/d1	R,$TMPDIR/d1	L," < $TWCONFIG > /tmp/twx
    mv /tmp/twx $TWCONFIG
    set _ $TRIPWIRE -d $TWDB -q -update $TMPDIR/d1/@1; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

    # check to that ignore-masks are different
    grep "$TMPDIR/d1" ./databases/* | awk '{ print $3; }' > /tmp/tw1
    grep "$TMPDIR/d1" $TWDB | awk '{ print $3; }' > /tmp/tw2
    echo "diffing" >> $LOGFILE
    diff /tmp/tw1 /tmp/tw2 >> $LOGFILE
    if [ $? -ne 1 ]; then
	echo "=== $ME: test diff FAILED! (expecting 1, got $?) ==="
	echo "=== ($LOGFILE contains output from test script and Tripwire) ==="
	exit 1
    fi

echo "=== $ME:  changed ignore-mask (UPDATE entry)"
    touch $TMPDIR/d1/@1
    set _ $TRIPWIRE -q ; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSCHA; shift
    . $MYCHECK 

    # change the ignore mask
    sed "s,$TMPDIR/d1	R,$TMPDIR/d1	L," < $TWCONFIG > /tmp/twx
    mv /tmp/twx $TWCONFIG
    set _ $TRIPWIRE -d $TWDB -q -update $TMPDIR/d1; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

    # check to that ignore-masks are different
    grep "$TMPDIR/d1" ./databases/* | awk '{ print $3; }' > /tmp/tw1
    grep "$TMPDIR/d1" $TWDB | awk '{ print $3; }' > /tmp/tw2
    echo "diffing" >> $LOGFILE
    diff /tmp/tw1 /tmp/tw2 >> $LOGFILE
    if [ $? -ne 1 ]; then
	echo "=== $ME: test diff FAILED! (expecting 1, got $?) ==="
	echo "=== ($LOGFILE contains output from test script and Tripwire) ==="
	exit 1
    fi

echo "=== $ME: testing UPDATED files (6 cases)"
    . $MYCREATE
    . $MYCREATETWCONF
    . $MYINIT

echo "=== $ME:  case 1: update: add new file ==="
    cp $SAVETWDB ./databases
    touch $NEWFILE
    set _ $TRIPWIRE -q ; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSADD; shift
    . $MYCHECK 
    set _ $TRIPWIRE -d $TWDB -q -update $NEWFILE; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

    # move database
    rm -f databases/*.old
    cp databases/tw.db* $TWDB

    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

echo "=== $ME:  case 2: update: delete file ==="
    rm -f $OLDFILE
    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSDEL; shift
    . $MYCHECK 
    set _ $TRIPWIRE -d $TWDB -q -update $OLDFILE; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 
    
    # move database
    rm -f databases/*.old
    cp databases/tw.db* $TWDB

    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

CFILE=$TMPDIR/d1/@1
CDIR=$TMPDIR/d1

echo "=== $ME:  case 3: update: update file ==="
    touch $CFILE
    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSCHA; shift
    . $MYCHECK 
    set _ $TRIPWIRE -d $TWDB -q -update $CFILE; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

    # move database
    rm -f databases/*.old
    cp databases/tw.db* $TWDB

    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

echo "=== $ME:  case 4: nonsense case (skipping) ==="

echo "=== $ME:  case 6: update: delete entry ==="
    rm -rf $CDIR
    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSDEL; shift
    . $MYCHECK 
    set _ $TRIPWIRE -d $TWDB -q -update $CDIR; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

    # move database
    rm -f databases/*.old
    cp databases/tw.db* $TWDB

    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

echo "=== $ME:  case 5: update: add entry ==="
    mkdir $CDIR
    touch $CDIR/@1
    set _ $TRIPWIRE -q ; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSADD; shift
    . $MYCHECK 
    set _ $TRIPWIRE -d $TWDB -q -update $CDIR; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

    # move database
    rm -f databases/*.old
    cp databases/tw.db* $TWDB

    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

CFILE=$TMPDIR/d2/@1
CDIR=$TMPDIR/d2

echo "=== $ME:  case 7: update: update entry ==="
    touch $CFILE
    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) > $LOGFILE; 
    set _ $STATUSCHA; shift
    . $MYCHECK 
    set _ $TRIPWIRE -d $TWDB -q -update $CDIR; shift
    ( . $MYRUN ; ) >> $LOGFILE; 
    set _ 0; shift
    . $MYCHECK 

    # move database
    rm -f databases/*.old
    cp databases/tw.db* $TWDB

    set _ $TRIPWIRE -q; shift
    ( . $MYRUN ; ) >> $LOGFILE ; 
    set _ 0; shift
    . $MYCHECK 

echo "=== $ME: PASS ==="


echo 
echo
