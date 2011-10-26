#!/bin/sh
#
# 
# $Id: make-uml.sh,v 1.14.2.1 2002/04/07 17:33:30 mcr Exp $
#

# show me
set -x

# fail if any command fails
set -e

case $# in
    1) FREESWANSRCDIR=$1; shift;;
esac
    
#
# configuration for this file has moved to $FREESWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at umlsetup-sample.sh
# in this directory. Copy it to $FREESWANSRCDIR and edit it.
#
FREESWANSRCDIR=${FREESWANSRCDIR-../..}
if [ ! -f ${FREESWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in umlsetup-sample.sh.
    exit 1
fi

. ${FREESWANSRCDIR}/umlsetup.sh
. ${FREESWANSRCDIR}/testing/utils/uml-functions.sh

# set this to a freshly checked out repository/snapshot
FREESWANSRCDIR=${FREESWANSRCDIR-/c2/freeswan/sandbox}

# make absolute so that we can reference it from POOLSPACE
FREESWANSRCDIR=`cd $FREESWANSRCDIR && pwd`;export FREESWANSRCDIR

if [ -d $FREESWANSRCDIR/testing/kernelconfigs ]
then
    TESTINGROOT=$FREESWANSRCDIR/testing
fi
TESTINGROOT=${TESTINGROOT-/c2/freeswan/sandbox/testing}

# okay, copy the kernel, apply the UML patches, and build a plain kernel.
UMLPLAIN=$POOLSPACE/plain
mkdir -p $UMLPLAIN

if [ ! -x $UMLPLAIN/linux ]
then
    cd $UMLPLAIN
    lndir -silent $KERNPOOL .
    
    if [ ! -d arch/um ] 
    then
	bzcat $UMLPATCH | patch -p1 
    fi

    if [ ! -f .config ] 
    then
	cp ${TESTINGROOT}/kernelconfigs/umlplain.config .config
    fi
    (make ARCH=um oldconfig && make ARCH=um dep && make ARCH=um linux ) || exit 1
fi

# now, setup up root dir
for host in $REGULARHOSTS
do
    setup_host $host $UMLPLAIN/linux
done

# now, copy the kernel, apply the UML patches.
# then, make FreeSWAN patches as well.
#
UMLSWAN=$POOLSPACE/swan

# we could copy the UMLPLAIN to make this tree. This would be faster, as we
# already built most everything. We could also just use a FreeSWAN-enabled
# kernel on sunrise/sunset. We avoid this as we actually want them to always
# work.

# where to install FreeSWAN tools
DESTDIR=$POOLSPACE/root

# do not generate .depend by default
KERNDEP=''

mkdir -p $UMLSWAN

if [ ! -x $UMLSWAN/linux ]
then
    cd $UMLSWAN
    lndir -silent $KERNPOOL .
    
    if [ ! -d arch/um ] 
    then
	bzcat $UMLPATCH | patch -p1 
    fi
    
    # copy the config file
    rm -f .config
    cp ${TESTINGROOT}/kernelconfigs/umlswan.config .config

    # make the kernel here for good luck
    make ARCH=um oldconfig
    if [ ! -f .depend ]
    then
      make ARCH=um dep >umlswan.make.dep.out
    fi 
    make ARCH=um linux >umlswan.make.plain.out

    # we have to copy it again, because "make oldconfig" above, blew
    # away options that it didn't know about.

    cp ${TESTINGROOT}/kernelconfigs/umlswan.config .config

    # nuke final executable here since we will do FreeSWAN in a moment.
    rm -f linux .depend
    KERNDEP=dep
fi

grep CONFIG_IPSEC $UMLSWAN/.config || exit 1

#if [ ! -f $FREESWANSRCDIR/Makefile ] || [ ! -f $FREESWANSRCDIR/pluto/version.c ]
if [ ! -f $FREESWANSRCDIR/Makefile ]
then
  if [ ! -f $FREESWANSRCDIR/top/Makefile ]
  then
	    echo "No Makefile and no top/Makefile. You must check out 'all'!"
	    exit 10
  fi
  (cd $FREESWANSRCDIR/top && make devready )
fi

if [ ! -x $UMLSWAN/linux ]
then
    cd $FREESWANSRCDIR || exit 1

    make KERNMAKEOPTS='ARCH=um' KERNELSRC=$UMLSWAN KERNCLEAN='' KERNDEP=$KERNDEP KERNEL=linux DESTDIR=$DESTDIR oldgo || exit 1
fi

cd $FREESWANSRCDIR || exit 1

make programs

# now, setup up root dir
for host in $FREESWANHOSTS
do
    setup_host $host $UMLSWAN/linux
    cd $FREESWANSRCDIR && make DESTDIR=$POOLSPACE/$host/root install
    cd $FREESWANSRCDIR/utils && make DESTDIR=$POOLSPACE/$host/root setup4
done




    
    
    
#
# $Log: make-uml.sh,v $
# Revision 1.14.2.1  2002/04/07 17:33:30  mcr
#    fixes for make-uml desires for building static UML kernels
#
# Revision 1.15  2002/04/05 01:21:39  mcr
# 	make-uml script was building statically linked FreeSWAN kernels
# 	only by fluke - turns out that "make oldconfig" blows away
# 	any options in .config that weren't defined. Thus, the initial
# 	build of a non-SWAN kernel before building FreeSWAN would
# 	blow away the CONFIG_IPSEC options- specifically the CONFIG_IPSEC=y
# 	(vs =m). This worked before because "make insert" put the
# 	options back in, but now that the default has changed to modules,
# 	the it defaults the wrong way.
# 	Solution: copy the .config file in again after the plain build.
#
# Revision 1.14  2002/04/03 23:42:18  mcr
# 	force copy of swan kernel config file to get right IPSEC=y options.
# 	redirect some build output to a local file.
#
# Revision 1.13  2002/02/16 20:56:06  rgb
# Force make programs so UML does not depend on top level make programs.
#
# Revision 1.12  2002/02/13 21:39:16  mcr
# 	change to use uml*.config files instead.
# 	uml*.config files have been updated for 2.4.7-10 UML patch.
#
# Revision 1.11  2002/01/11 05:26:03  rgb
# Fixed missing semicolon bug.
#
# Revision 1.10  2001/11/27 05:36:30  mcr
# 	just look for a kernel in build directory. This
# 	type of "optomization" is dumb - it should be a makefile.
#
# Revision 1.9  2001/11/23 00:36:01  mcr
# 	take $FREESWANDIR as command line argument.
# 	use HS's "devready" instead of fudging our own.
#
# Revision 1.8  2001/11/22 05:46:07  henry
# new version stuff makes version.c obsolete
#
# Revision 1.7  2001/11/07 20:10:20  mcr
# 	revised setup comments after RGB consultation.
# 	removed all non-variables from umlsetup-sample.sh.
#
# Revision 1.6  2001/11/07 19:25:17  mcr
# 	split out some functions from make-uml.
#
# Revision 1.5  2001/10/28 23:52:22  mcr
# 	pathnames need to be fully qualified.
#
# Revision 1.4  2001/10/23 16:32:08  mcr
# 	make log files unique to each UML.
#
# Revision 1.3  2001/10/15 05:41:46  mcr
# 	moved variables for UML setup to common file.
# 	provided sample of this file.
#
# Revision 1.2  2001/09/25 01:09:53  mcr
# 	some minor changes to whether to run "KERNDEP"
#
# Revision 1.1  2001/09/25 00:52:16  mcr
# 	a script to build a UML+FreeSWAN testing environment.
#
#    
