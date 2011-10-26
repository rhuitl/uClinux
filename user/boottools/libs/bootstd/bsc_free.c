/*
 * bsc_gc.c
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
 * functions: 	int bsc_free(void);
 *		int bsc_gc(void); run garbage collection
 *
 * parameters:  none
 *
 * returns:	return free flash space for the environment variable
 *		in bytes.
 */

#include <bootstd.h>

#if defined(__BN_gc)

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

static _bsc1 (int, gc, int, a)

int
bsc_free (void)
{
    return ( gc(0) );
}

int
bsc_gc (void)
{
    return ( gc(1) );
}

#else

int
bsc_free (void)
{
    int bscfd;
    int ret;

    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return -1;
    ret = ioctl(bscfd, __BN_gc, 0);
    close(bscfd);

    return ( ret );
}

int
bsc_gc (void)
{
    int bscfd;
    int ret;

    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return -1;
    ret = ioctl(bscfd, __BN_gc, 1);
    close(bscfd);

    return ( ret );
}

#endif

#else

#warning "BSC SYSCALL for __BN_gc not available"

int
bsc_free (void)
{
   return (-404);
}

int
bsc_gc (void)
{
   return (-404);
}

#endif
