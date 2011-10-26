/*
 * bsc_gethwaddr.c
 *
 * Copyright (c) 2006  Arcturus Networks Inc.
 *	by Oleksandr G Zhadan <www.ArcturusNetworks.com>
 *
 * All rights reserved.
 *
 * This material is proprietary to Arcturus Networks Inc. and, in
 * addition to the above mentioned Copyright, may be subject to
 * protection under other intellectual property regimes, including
 * patents, trade secrets, designs and/or trademarks.
 *
 * Any use of this material for any purpose, except with an express
 * license from Arcturus Networks Inc. is strictly prohibited.
 *
 * format: 	char *bsc_gethwaddr(int devnum, char *value);
 *		return the MAC address of the requested device
 *
 * parameters:  devnum - eth device nummder (0, 1, ...)
 *		value - prealocated space for returned value
 *
 * returns:	the poiner to the value of the MAC address
 *		if the interface wasn't found than pointer to eth0 address or
 *		0 on error
 */

#include <bootstd.h>
#include <errno.h>

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

#if BSC_MMU

static _bsc2(char *, gethwaddr, int, a, char *, b)

char *
bsc_gethwaddr ( int devnum, char *hwaddr )
{
    if  ( !hwaddr )  return 0;
    gethwaddr(devnum, hwaddr);
    return hwaddr;
}

#else

static _bsc1(char *, gethwaddr, int, a)

char *
bsc_gethwaddr ( int devnum, char *value )
{
    char *src = gethwaddr(devnum);
    char *dst = value;
    if  ( (unsigned int)src != 0 ) {
	while ( *src )	*dst++ = *src++;
	*dst = 0;
	return value;
	}
    return src;
}

#endif

#else

char *
bsc_gethwaddr ( int devnum, char *hwaddr )
{
    int bscfd;
    int ret = 0;
    bsc_op_t bget;
    
    if  ( !hwaddr )
	return (char *)ret;

    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return (char *)ret;

    bget.arg1 = devnum;
    bget.arg2 = hwaddr;
    bget.arg3 = 6;
    ret = ioctl(bscfd, __BN_gethwaddr, (void *)&bget);

    close(bscfd);

    return ((char *)ret);
}

#endif	/* KERNEL_BSC_IOCTL_SUPPORT */
