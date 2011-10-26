/*
 * bsc_readenv.c
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
 * format: 	int  bsc_readenv(int operation, char *buff, int size);
 *		read environment variable names/values
 *
 * parameters:
 *		operation:
 *			0/default - read first environment variable name
 *			1 - read next environment variable name
 *			2 - read current environment variable's value
 *		
 *		buff - prealocated space for returned value
 *		size - sizeof(buff)
 *
 * returns:	length of the environment variable (in bytes)
 *		0 if no or no more environment variables found or error
 */

#include <string.h>
#include <bootstd.h>
#include <errno.h>

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

#if BSC_MMU
static _bsc2(char *, readbenv, int, a, char *, b)

#else
static _bsc1(char *, readbenv, int, a)

#endif

int
bsc_readenv ( int op, char *buff, int size )
{
    char *ret;
    int len = 0;
#if defined(BSC_SEMAPHORE_SUPPORT)
    int sid, rsid;
#endif
#if BSC_MMU
    char tmpbuff[MAX_ENVDATA_SIZE];
#endif
    if  ( !buff )
	return 0;

#if defined(BSC_SEMAPHORE_SUPPORT)
    sid = bsc_sem_open();
    if  ( op == 0 ) {
	if  ( (rsid=bsc_sem_lock(sid)) ) {
	    printf ("bsc_readenv: BSC_SEM locked ...%d\n", rsid);
	    return 0;
	    }
	}
#endif

#if BSC_MMU
    memset ( tmpbuff,  0, MAX_ENVDATA_SIZE );
    ret = readbenv(op, (char *)tmpbuff);
    if  ( (unsigned int)ret > 0 ) {
	len = strlen((char *)tmpbuff);
	if  ( len >= size ) {
#if defined(BSC_SEMAPHORE_SUPPORT)
	    bsc_sem_unlock(sid);
#endif
	    return 0;
	    }
	memcpy ( buff, tmpbuff, len);
	buff[len]=0;
	}
#else
    ret = readbenv(op);
    if  ( (unsigned int)ret > 0 ) {
	len = strlen(ret);
	if  ( len >= size ) {
#if defined(BSC_SEMAPHORE_SUPPORT)
	    bsc_sem_unlock(sid);
#endif
	    return 0;
	    }
	memcpy ( buff, ret, len);
	buff[len]=0;
        }
#endif

#if defined(BSC_SEMAPHORE_SUPPORT)
    if  ( ret == 0 )
	bsc_sem_unlock(sid);
#endif

    return len;
}

#else

int
bsc_readenv ( int op, char *buff, int size )
{
    int ret = 0;
    int bscfd;
    bsc_op_t bread;

    if  ( !buff || (size < 2) || (op > 2) )
	return ret;

    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return ret;

    bread.arg1 = op;
    bread.arg2 = buff;
    bread.arg3 = size;
    ret = ioctl(bscfd, __BN_readbenv, (void *)&bread);

    close(bscfd);
    return ret;
}

#endif	/* KERNEL_BSC_IOCTL_SUPPORT */
