#! /bin/sh
#############################################################################

#
# update-configs -- update all new-wave vendor configs
#
# (C) Copyright 2003, Greg Ungerer <gerg@snapgear.com>
#
# 2005/08/11 -  Added ability to specify a specific VENDOR, BOARD, and KERNEL
# -- Zachary P. Landau <kapheine@divineinvasion.net>
#

#############################################################################

#
# Figure out the vendor/products dynamically, allows people to add their
# own without messing with the config.in file.
#
# Usage: $0 [VENDOR] [BOARD] [KERNEL]

if [ $1 ]; then
    VENDORLIST=$1
else
    VENDORLIST=`find vendors/*/*/config.arch -print | sed -e 's?/? ?g' | sort |
        while read t1 v p t2
        do
            echo "${v}"
        done | uniq`
fi


for VENDOR in $VENDORLIST
do
    if [ $2 ]; then
        BOARDLIST=$2
    else
        BOARDLIST=`find vendors/${VENDOR}/*/config.arch -print |
        sed -e 's?/? ?g' | sort |
        while read t1 v p t2
        do
            echo "${p}"
        done`
    fi

    for BOARD in $BOARDLIST
    do

        if [ $3 ]; then
            KERNELLIST=$3
        else
            KERNELLIST="linux-2.0.x linux-2.4.x linux-2.6.x"
        fi

        for KERNEL in $KERNELLIST
        do
            rm -f .config .config.old .oldconfig
            rm -f ${KERNEL}/.config ${KERNEL}/.config.old
            rm -f config/.config config/.config.old
            rm -f uClibc/.config uClibc/.config.old
            rm -f config.arch

            if [ -f vendors/${VENDOR}/${BOARD}/config.uClibc ]
            then
                LIBC=uClibc
            else
                LIBC=uC-libc
            fi

            if [ -f vendors/${VENDOR}/${BOARD}/config.${KERNEL} ]
            then
                ( echo $VENDOR ;
                sleep 1 ;
                echo $BOARD ;
                sleep 1 ;
                echo $KERNEL ;
                sleep 1 ;
                echo $LIBC ;
                sleep 1 ;
                echo ;
                sleep 1 ;
                echo ;
                sleep 1 ;
                echo ;
                echo y ;
                while : ; do echo ; done
                ) | make config
            fi
        done
    done
done

exit 0

