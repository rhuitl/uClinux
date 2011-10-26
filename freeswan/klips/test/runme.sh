#!/bin/sh

#
# $Id: runme.sh,v 1.3 2002/04/02 02:48:21 mcr Exp $
#
# use this script to run a single test from within that test directory.
# note that this assumes a "klipstest" type test.
#

. ../../../umlsetup.sh
. ../setup.sh
. ../functions.sh
. testparams.sh

( netjigtest )

stat=$?
testdir=$TESTNAME
testtype=klipstest

(cd .. && recordresults $testdir $testtype $stat)

 
# $Log: runme.sh,v $
# Revision 1.3  2002/04/02 02:48:21  mcr
# *** empty log message ***
#
# Revision 1.2  2001/11/23 01:08:12  mcr
# 	pullup of test bench from klips2 branch.
#
# Revision 1.1.2.1  2001/10/23 02:27:14  mcr
# 	more setup and utility scripts.
#
# 

