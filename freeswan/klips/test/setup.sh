
if [ -z "$FREESWANSRCDIR" ]
then
	if [ -f ../../umlsetup.sh ]
	then
	  FREESWANSRCDIR=`cd ../.. && pwd`
	else 
	  if [ -f ../../../umlsetup.sh ]
	  then 
	    FREESWANSRCDIR=`cd ../../.. && pwd`
	  fi
        fi  	
fi

if [ ! -f $FREESWANSRCDIR/umlsetup.sh ]
then
	echo Umlsetup not found at FREESWANSRCDIR=$FREESWANSRCDIR.
	echo Is FREESWANSRCDIR set correctly'?'
	exit 5
fi

TESTINGROOT=${FREESWANSRCDIR}/testing
UTILS=`cd ${TESTINGROOT}/utils && pwd`
NJ=${UTILS}/uml_netjig/uml_netjig
KLIPSTOP=${FREESWANSRCDIR}/klips
FIXUPDIR=`cd ${KLIPSTOP}/test/fixups && pwd`
CONSOLEDIFFDEBUG=${CONSOLEDIFFDEBUG-false}
NETJIGDEBUG=${NETJIGDEBUG-false}

# find this on the path if not already set.
TCPDUMP=${TCPDUMP-tcpdump}

REGRESSRESULTS=${REGRESSRESULTS-results}


