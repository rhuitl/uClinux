#! /bin/sh 
#
# 
# $Id: uml-functions.sh,v 1.5 2002/04/04 00:19:02 mcr Exp $
#

setup_host() {
    host=$1
    KERNEL=$2
    KERNDIR=`dirname $KERNEL`

    hostroot=$POOLSPACE/$host/root
    mkdir -p $hostroot
    # copy (with hard links) 
    (cd ${BASICROOT} && find . -print | cpio -pld $hostroot 2>/dev/null )

    # make private copy of /var.
    rm -rf $hostroot/var
    (cd ${BASICROOT} && find var -print | cpio -pd $hostroot 2>/dev/null )

    # make sure that we have /dev, /tmp and /var/run
    mkdir -p $hostroot/dev $hostroot/tmp $hostroot/var/run $hostroot/usr/share $hostroot/proc

    # root image is debian, but FreeSWAN expects redhat
    mkdir -p $hostroot/etc/rc.d
    if [ ! -d $hostroot/etc/rc.d/init.d ]
    then
      (cd $hostroot/etc/rc.d && ln -fs ../init.d ../rc?.d . )
    fi
    
    # nuke certain other files that get in the way of booting
    rm -f $hostroot/etc/mtab
    rm -f $hostroot/sbin/hwclock

    # set up the timezone
    rm -f $hostroot/etc/localtime 

    # dummy out fsck.
    ln -f $hostroot/bin/true $hostroot/sbin/fsck.hostfs

    # force it to GMT, otherwise (RH7.1) use host's zoneinfo.
    if [ -f /usr/share/zoneinfo/GMT ] 
    then
      cp /usr/share/zoneinfo/GMT $hostroot/etc/localtime
    else
      cp /etc/localtime $hostroot/etc/localtime
    fi

    # or, you might want to force it to local
    # cp /etc/localtime $hostroot/etc/localtime

    # copy configuration files
    ### XXX this should be done with a generated Makefile.
    (cd ${TESTINGROOT}/baseconfigs/$host && tar cf - .) | (cd $hostroot && tar -x -f - --unlink-first)

    # split Debian "interfaces" file into RH ifcfg-* file
    mkdir -p $hostroot/etc/sysconfig/network-scripts
    ${TESTINGROOT}/utils/interfaces2ifcfg.pl $hostroot/etc/network/interfaces $hostroot/etc/sysconfig/network-scripts

    # copy kernel.
    if [ ! -f $POOLSPACE/$host/linux ]
    then
	rm -f $POOLSPACE/$host/linux
	cp $KERNEL $POOLSPACE/$host/linux
    fi

    # update the module, if any.
    if [ -f $KERNDIR/net/ipsec/ipsec.o ]
    then
	cp $KERNDIR/net/ipsec/ipsec.o $POOLSPACE/$host/root/ipsec.o
    fi

    # make startup script
    startscript=$POOLSPACE/$host/start.sh
    if [ ! -f $startscript ]
    then
	echo '#!/bin/sh' >$startscript
	echo ''          >>$startscript
	echo '# get $net value from baseconfig'          >>$startscript
	echo ". ${TESTINGROOT}/baseconfigs/net.$host.sh" >>$startscript
	echo ''          >>$startscript
	echo "$POOLSPACE/$host/linux ubd0=$hostroot ubd1=$SHAREDIR umid=$host \$net \$*" >>$startscript
	chmod +x $startscript
    fi
}

#
# $Log: uml-functions.sh,v $
# Revision 1.5  2002/04/04 00:19:02  mcr
# 	when setting up root file systems, see if we built an ipsec.o
# 	as part of the kernel build, and if so, copy it to /ipsec.o for
# 	later use.
#
# Revision 1.4  2002/01/12 02:50:29  mcr
# 	when removing /var to make private copy, make sure that
# 	-f(orce) is set.
#
# Revision 1.3  2001/11/23 00:38:41  mcr
# 	make /var private
# 	make fake fsck.hostfs
# 	split Debian interfaces file into RH file using script.
#
# Revision 1.2  2001/11/07 20:10:20  mcr
# 	revised setup comments after RGB consultation.
# 	removed all non-variables from umlsetup-sample.sh.
#
# Revision 1.1  2001/11/07 19:25:17  mcr
# 	split out some functions from make-uml.
#
#


