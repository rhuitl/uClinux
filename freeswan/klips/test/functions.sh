#!/bin/sh

consolediff() {
    cleanups="cat OUTPUT/console.txt "

    for fixup in `echo $REF_CONSOLE_FIXUPS`
    do
	if [ -f $FIXUPDIR/$fixup ]
	then
	    case $fixup in
		*.sed) cleanups="$cleanups | sed -f $FIXUPDIR/$fixup";;
		*.pl)  cleanups="$cleanups | perl $FIXUPDIR/$fixup";;
		*.awk) cleanups="$cleanups | awk -f $FIXUPDIR/$fixup";;
		    *) echo Unknown fixup type: $fixup;;
            esac
        fi
    done

    rm -f OUTPUT/console-fixed.txt OUTPUT/console.diff
    $CONSOLEDIFFDEBUG && echo Cleanups is $cleanups
    eval $cleanups >OUTPUT/console-fixed.txt
    if diff -u -w -b -B $REF_CONSOLE_OUTPUT OUTPUT/console-fixed.txt >OUTPUT/console.diff
    then
	echo "Console output matched"
    else
	echo "Console output differed"
	success=false
    fi
}

compat_variables() {
    if [ -z "$REF_CONSOLE_OUTPUT" ] && [ -n "$REFCONSOLEOUTPUT" ]
    then
	REF_CONSOLE_OUTPUT=$REFCONSOLEOUTPUT
    fi

    if [ -z "$REF_CONSOLE_FIXUPS" ] && [ -n "$REFCONSOLEFIXUPS" ]
    then
	REF_CONSOLE_FIXUPS=$REFCONSOLEFIXUPS
    fi

    if [ -z "$REF_PUB_OUTPUT" ] && [ -n "$REFPUBOUTPUT" ]
    then
	REF_PUB_OUTPUT=$REFPUBOUTPUT
    fi

    if [ -z "$REF_PRIV_OUTPUT" ] && [ -n "$REFPRIVOUTPUT" ]
    then
	REF_PRIV_OUTPUT=$REFPRIVOUTPUT
    fi
}

# this is called to set additional variables that depend upon testparams.sh
prerunsetup() {
    HOSTSTART=$POOLSPACE/$TESTHOST/start.sh

    compat_variables;
}

#
# record results records the status of each test in 
#   $REGRESSRESULTS/$testname/status
#
# If the status is negative, then the "OUTPUT" directory of the test is
# copied to $REGRESSRESULTS/$testname/OUTPUT as well.
#
# The file $testname/description.txt if it exists is copied as well.
#
# If $REGRESSRESULTS is not set, then nothing is done.
# 
# See testing/utils/regress-summarizeresults.pl for a tool to build a nice
# report from these files. 
#
# See testing/utils/regress-nightly.sh and regress-stage2.sh for code
# that sets up $REGRESSRESULTS.
# 
# usage: recordresults testname testtype status
#
recordresults() {
    testname=$1
    testtype=$2
    success=$3
    if [ -n "$REGRESSRESULTS" ]
    then
	mkdir -p $REGRESSRESULTS/$testname
	
	# note that 0/1 is shell sense.
	case $success in
	    0) success=true;;
	    1) success=false;;
	    true)  success=true;;
	    false) sucesss=false;;
	    succeed) success=true;;
	    fail)  success=false;;
	    yes)   success=true;;
	    no)    success=false;;
	    *) echo 'functions.sh:recordresults()' Bad value for success: $success >&2;
		exit 2;
         esac

	 echo $success >$REGRESSRESULTS/$testname/status

	 if [ -f $testname/description.txt ]
	 then
	    cp $testname/description.txt $REGRESSRESULTS/$testname
	 fi

	 if [ -n "$TEST_PURPOSE" ]
	 then
	    case $TEST_PURPOSE in
	    regress) echo ${TEST_PROB_REPORT} >$REGRESSRESULTS/$testname/regress.txt;;
	       goal) echo ${TEST_GOAL_ITEM}   >$REGRESSRESULTS/$testname/goal.txt;;
	    exploit) echo ${TEST_EXPLOIT_URL} >$REGRESSRESULTS/$testname/exploit.txt;;
	    esac
         fi

	 if $success
	 then
	    :
	 else
	    mkdir -p $REGRESSRESULTS/$testname/OUTPUT
	    tar cf - $testname/OUTPUT | (cd $REGRESSRESULTS && tar xf - )
	 fi
    fi
}

# The following variables need to be set before calling the tests
# 
#    TESTNAME          - the name of the test
#    SCRIPT            - a script to load on the console
#    PRIVINPUT         - a pcap file to feed on private side
#    PUBINPUT          - a pcap file to feed on the public side
#
#  If set, then the public and private packet output will be captured,
#  turned into ASCII with tcpdump, and diff'ed against these files.
#    REF_PRIVO_UTPUT   - for private side
#    REF_PUB_OUTPUT    - for public side
#    TCPDUMPARGS     - extra args for TCPDUMP.
#
#  If set, then the console output will be diff'ed against this file:
#    REF_CONSOLE_OUTPUT          
#  
#  The console output may need to be sanitized. The list of fixups from
# REF_CONSOLE_FIXUPS will be appled from "fixups". The extension is used to
# determine what program to use.
#
#  Some additional options to control the network emulator
#    EXITONEMPTY=--exitonempty   - if pcap file end should signal end of test
#    ARPREPLY=--arpreply         - if ARPs should be answered

    
netjigtest() {

    prerunsetup

    success=true

    PRIVOUTPUT=''
    PUBOUTPUT=''
    
    mkdir -p OUTPUT

    NJARGS=''

    if [ -n "$PRIVINPUT" ]
    then
	NJARGS="$NJARGS --playprivate $PRIVINPUT"
    fi

    if [ -n "$PUBINPUT" ]
    then
	NJARGS="$NJARGS --playpublic $PUBINPUT"
    fi

    if [ -n "$REF_PRIV_OUTPUT" ]
    then
	PRIVOUTPUT=`basename $REF_PRIV_OUTPUT .txt `
	NJARGS="$NJARGS --recordprivate OUTPUT/$PRIVOUTPUT.pcap"
    fi

    if [ -n "$REF_PUB_OUTPUT" ]
    then
	PUBOUTPUT=`basename $REF_PUB_OUTPUT .txt`
	NJARGS="$NJARGS --recordpublic OUTPUT/$PUBOUTPUT.pcap"
    fi

    if [ -n "$NETJIGARGS" ]
    then
	NJARGS="$NJARGS $NETJIGARGS"
    fi

    rm -f OUTPUT/console.txt
    $NETJIGDEBUG && echo $NJ --tcpdump $ARPREPLY $EXITONEMPTY $NJARGS --startup "expect -f $UTILS/host-test.tcl $HOSTSTART ${SCRIPT} " 
    $NJ --tcpdump $ARPREPLY $EXITONEMPTY `eval echo $NJARGS` --startup "expect -f $UTILS/host-test.tcl $HOSTSTART ${SCRIPT} >OUTPUT/console.txt" 

    uml_mconsole $TESTHOST halt

    if [ -z "$REF_PRIV_FILTER" ]
    then
	REF_PRIV_FILTER=cat
    fi

    if [ -n "$PRIVOUTPUT" ]
    then
	rm -f OUTPUT/$PRIVOUTPUT.txt
	echo $TCPDUMP -t $TCPDUMPFLAGS -r OUTPUT/$PRIVOUTPUT.pcap '>'OUTPUT/$PRIVOUTPUT.txt
	eval $TCPDUMP -t $TCPDUMPFLAGS -r OUTPUT/$PRIVOUTPUT.pcap | $REF_PRIV_FILTER >OUTPUT/$PRIVOUTPUT.txt

	rm -f OUTPUT/$PRIVOUTPUT.diff
	if diff -u -w -b -B $REF_PRIV_OUTPUT OUTPUT/$PRIVOUTPUT.txt >OUTPUT/$PRIVOUTPUT.diff
	then
	    echo "Private side output matched"
	else
	    echo "Private side output failed"
	    success=false
	fi
    fi


    if [ -z "$REF_PUB_FILTER" ]
    then
	REF_PUB_FILTER=cat
    fi

    if [ -n "$PUBOUTPUT" ]
    then
	rm -f OUTPUT/$PUBOUTPUT.txt
	echo $TCPDUMP -t $TCPDUMPFLAGS -r OUTPUT/$PUBOUTPUT.pcap '>'OUTPUT/$PUBOUTPUT.txt
	eval $TCPDUMP -t $TCPDUMPFLAGS -r OUTPUT/$PUBOUTPUT.pcap | $REF_PUB_FILTER >|OUTPUT/$PUBOUTPUT.txt

	rm -f OUTPUT/$PUBOUTPUT.diff
	if diff -u -w -b -B $REF_PUB_OUTPUT OUTPUT/$PUBOUTPUT.txt >OUTPUT/$PUBOUTPUT.diff
	then
	    echo "Public  side output matched"
	else
	    echo "Public  side output failed"
	    success=false
	fi
    fi

    if [ -n "$REF_CONSOLE_OUTPUT" ]
    then
        consolediff
    fi
    if $success
    then
	exit 0
    else
	exit 1
    fi
}

    
umltest() {
    mkdir -p OUTPUT
    success=true

    prerunsetup

    rm -f OUTPUT/console.txt
    expect -f $UTILS/host-test.tcl $HOSTSTART ${SCRIPT} >OUTPUT/console.txt

    if [ -n "$REFCONSOLEOUTPUT" ]
    then
	consolediff
    fi
    if $success
    then
	exit 0
    else
	exit 1
    fi
}


klipstest() {
    testdir=$1
    testtype=$2

    echo '*******  KLIPS RUNNING' $testdir '*******' 

    if [ ! -r $testdir/testparams.sh ]
    then
	echo '      ' No configuration
	return
    fi
    ( cd $testdir && . ./testparams.sh && netjigtest )
    stat=$?
    recordresults $testdir $testtype $stat
    if [ $stat = 0 ]
    then
	echo '*******  PASSED '$testdir' ********'
    else
	echo '*******  FAILED '$testdir' ********'
    fi
}

ctltest() {
    testdir=$1
    testtype=$2

    echo '*******  KERN  RUNNING' $testdir '*******' 

    if [ ! -r $testdir/testparams.sh ]
    then
	echo '      ' No configuration
	return
    fi
    ( cd $testdir && . ./testparams.sh && umltest )
    stat=$?
    recordresults $testdir $testtype $stat
    if [ $stat = 0 ]
    then
	echo '*******  PASSED '$testdir' ********'
    else
	echo '*******  FAILED '$testdir' ********'
    fi
}

skiptest() {
    testdir=$1
    testtype=$2

    echo '*******  NOT   RUNNING' $testdir '*******' 
}
