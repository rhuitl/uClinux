/*
 * bsc_setpmask.c
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
 * format:	int bsc_setpmask(unsigned int mask);
 *		set environment variables protection make
 *
 * parameters:	mask - the new protection mask value desired
 *
 * returns:	0 - always returned
 */

#include <bootstd.h>
#include <errno.h>

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

static _bsc1 (int, setpmask, unsigned int, a)

int
bsc_setpmask ( unsigned int mask )
{
    return (setpmask(mask));
}

#else

int
bsc_setpmask ( unsigned int mask )
{
    int bscfd;
    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return -1;
    ioctl(bscfd, __BN_setpmask, mask);
    close (bscfd);
    return 0;
}

#endif
