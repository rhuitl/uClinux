#!/bin/sh

TESTING=../../../testing
UTILS=${TESTING}/utils
NJ=${UTILS}/uml_netjig/uml_netjig
UMLBUILD=/c2/freeswan/umlbuild
TESTHOST=east
HOSTSTART=$UMLBUILD/$TESTHOST/start.sh
TESTNAME=east-icmp-01
EXITONEMPTY=--exitonempty
REGRESSPLACE=.

mkdir -p OUTPUT

$NJ --tcpdump --arpreply $EXITONEMPTY --startup "expect -f $UTILS/host-test.tcl $HOSTSTART spi1.sh" --playprivate ../inputs/01-sunrise-sunset-ping.pcap --recordpublic OUTPUT/01-sunrise-sunset-ping-out.pcap

uml_mconsole /tmp/uml/$TESTHOST/mconsole <<EOF
halt
EOF

tcpdump -x -r OUTPUT/01-sunrise-sunset-ping-out.pcap >OUTPUT/01-sunrise-sunset-ping-out.txt

if diff -w spi1-output.txt OUTPUT/01-sunrise-sunset-ping-out.txt
then
    touch $REGRESSPLACE/$TESTNAME
else
    rm -f $REGRESSPLACE/$TESTNAME
    exit 1
fi


