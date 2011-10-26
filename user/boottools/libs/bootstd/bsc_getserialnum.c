/*
 * bsc_getserialnum.c
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
 * format: 	char *bsc_getserialnum(char *value);
 *		return the board serial number
 *
 * parameters:  value - prealocated space for returned value
 *
 * returns:	the poiner to the value of the serial number
 *		or pointer to the (char *)"none" if no serial number found
 *		or 0 on error;
 */

#include <bootstd.h>
#include <errno.h>

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

#if BSC_MMU

static _bsc1(char *, getserialnum, char *, a)

char *
bsc_getserialnum (char *sn)
{
    if  ( !sn )	return 0;
    getserialnum (sn);
    return sn;
}

#else

static _bsc0(char *, getserialnum)

char *
bsc_getserialnum ( char *value )
{
    char *src = getserialnum();
    char *dst = value;
    if ( (unsigned int) src != 0 ) {
	while ( *src )	*dst++ = *src++;
	*dst = 0;
	return value;
	}
    return src;
}

#endif

#else

char *
bsc_getserialnum (char *sn)
{
    int bscfd;
    int ret = 0;

    if  ( !sn )	return (char *)0;

    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return (char *)ret;
    ret = ioctl(bscfd, __BN_getserialnum, (unsigned int)sn);
    close(bscfd);

    return ((char *)ret);
}

#endif	/* KERNEL_BSC_IOCTL_SUPPORT */
