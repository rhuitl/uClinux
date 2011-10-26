#!/bin/sh 

# This script is used to setup the regression testing environment
# invoke the tests and record the results. It expects the following
# variables to be in the environment.
#
#    $BUILDSPOOL
#    $BRANCH            the name of the branch, or HEAD.
#    $TODAY             today's date.
#
# it is expected that $BUILDSPOOL/freeswan contains a checked out copy
# of the source tree that is ready for building. 
#
# In general, this script is in fact running from
#    $BUILDSPOOL/freeswan/testing/utils/regress-stage2.sh
#
# invoked from regress-nightly.sh. The two stages permit the regress-nightly.sh
# scritpt, which must be invoked from outside of the CVS tree to change
# very seldom.
#
# This script will further look for $HOME/freeswan-regress-env.sh for a list 
# of variables to include.
#
# This should include
#

# die if anything dies.
set -e

mkdir -p $BUILDSPOOL/UMLPOOL

umlsetup=$BUILDSPOOL/freeswan/umlsetup.sh

echo "#" `date`                                                     >$umlsetup
echo "POOLSPACE=$BUILDSPOOL/UMLPOOL"                               >>$umlsetup
echo "BUILDTOP=$BUILDSPOOL/freeswan export BUILDTOP"               >>$umlsetup

# freeswan-regress-eng.sh should have the following variables
# defined. This should be the only local configuration required.
# 
# KERNPOOL=/abigail/kernel/linux-2.4.17
# UMLPATCH=/abigail/user-mode-linux/uml-patch-2.4.17-4.bz2
# BASICROOT=/abigail/user-mode-linux/root-6.0
# SHAREDIR=${BASICROOT}/usr/share
#
# Please see doc/umltesting.html for details on filling in these variables.
#

if [ -f $HOME/freeswan-regress-env.sh ]
then
    cat $HOME/freeswan-regress-env.sh                              >>$umlsetup
    . $HOME/freeswan-regress-env.sh
fi

echo "FREESWANDIR=\$BUILDTOP"                                      >>$umlsetup
echo "REGULARHOSTS='sunrise sunset nic'"                           >>$umlsetup
echo "FREESWANHOSTS='east west japan'"                             >>$umlsetup

# setup regression test recording area.
REGRESSRESULTS=${REGRESSTREE}/${BRANCH}/${TODAY} export REGRESSRESULTS
mkdir -p ${REGRESSRESULTS}

perl -e 'print time()."\n";' >${REGRESSRESULTS}/datestamp

cd $BUILDSPOOL/freeswan && make check

perl $BUILDSPOOL/freeswan/testing/utils/regress-summarize-results.pl $REGRESSRESULTS









