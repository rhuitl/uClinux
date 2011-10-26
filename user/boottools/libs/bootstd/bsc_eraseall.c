/*
 * bsc_eraseall.c
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
 * format:	int bsc_eraseall(void);
 *		erase the environment variables flash memory
 *
 * returns:	0 - always returned
 */

#include <bootstd.h>
#include <errno.h>

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

static _bsc0 (int, erase)

int
bsc_eraseall (void)
{
    int ret;
#if defined(BSC_SEMAPHORE_SUPPORT)
    int sid;
    sid = bsc_sem_open();
    if  ( bsc_sem_lock(sid) ) {
	printf ("bsc_printenv: BSC_SEM locked ...\n");
	return -1;
	}
#endif

    ret = erase();

#if defined(BSC_SEMAPHORE_SUPPORT)
    bsc_sem_unlock(sid);
#endif

    return(ret);
}

#else

int
bsc_eraseall (void)
{
    int bscfd;

    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return -1;
    ioctl(bscfd, __BN_erase);
    close(bscfd);

    return 0;
}

#endif
