#!/bin/sh

#
# This is the nightly build script.
# It does almost nothing since the process itself is kept in CVS.
#
# This causes some bootstrap problems, but we deal with that by understanding
# that this first stage bootstrap can not updated automatically. This script
# should be copied somewhere that is not in the release tree (i.e. ~/bin) 
# and invoked periodically. 
#

if [ -f $HOME/freeswan-regress-env.sh ]
then
    . $HOME/freeswan-regress-env.sh
fi

# /btmp is a place with a bunch of space. 
BTMP=${BTMP:-/btmp} export BTMP

# CVSROOT is set if not already set to the repository location.
# if remote, make sure you have cvs login done already.
CVSROOT=${CVSROOT:-/freeswan/MASTER} export CVSROOT

# BRANCH can also be set to test branches.
BRANCH=${BRANCH:-HEAD} export BRANCH

# rest of not to be touched.
TODAY=`date +%Y_%m_%d` export TODAY

BUILDSPOOL=$BTMP/$USER/$BRANCH/$TODAY export BUILDSPOOL
mkdir -p $BUILDSPOOL || exit 3

cd $BUILDSPOOL || exit 4

exec >$BUILDSPOOL/stdout.txt
exec 2>$BUILDSPOOL/stderr.txt

cvs -Q -d $CVSROOT checkout -r $BRANCH freeswan

if [ $? != 0 ]
then
        echo "Failed to checkout source code. "
        exit 10
fi

# invoke file space cleanup first.
chmod +x $BUILDSPOOL/freeswan/testing/utils/regress-cleanup.pl 
$BUILDSPOOL/freeswan/testing/utils/regress-cleanup.pl || exit 5

# invoke stage 2 now.
chmod +x $BUILDSPOOL/freeswan/testing/utils/regress-stage2.sh  
$BUILDSPOOL/freeswan/testing/utils/regress-stage2.sh  || exit 6

# warn about changes in myself.
cmp $BUILDSPOOL/freeswan/testing/utils/regress-nightly.sh $0
	
if [ $? != 0 ]
then
    echo WARNING $BUILDSPOOL/freeswan/testing/utils/regress-nightly.sh differs from $0.
fi

# $Id: regress-nightly.sh,v 1.5 2002/02/12 04:09:46 mcr Exp $
#
# $Log: regress-nightly.sh,v $
# Revision 1.5  2002/02/12 04:09:46  mcr
# 	redirect and save stdout and stderr.
#
# Revision 1.4  2002/02/11 22:05:28  mcr
# 	initial scripts to export REGRESSRESULTS to support
# 	saving of testing results to a static area.
#
# Revision 1.3  2002/01/12 03:34:33  mcr
# 	an errant BUILDTOP remained. -> BUILDSPOOL.
#
# Revision 1.2  2002/01/11 22:14:31  mcr
# 	change BUILDTOP -> BUILDSPOOL.
# 	chmod +x all the scripts, just in case.
#
# Revision 1.1  2002/01/11 04:26:48  mcr
# 	revision 1 of nightly regress scripts.
#
#

