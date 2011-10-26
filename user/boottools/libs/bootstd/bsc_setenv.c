/*
 * bsc_setenv.c
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
 * format:	int bsc_setenv(char *pair );
 *		set a Flash environment variable to a value
 *
 * parameters:	pair - a string containing "envVarName=envVarValue"
 *
 * returns:	negative - if pair == NULL or error garbage collecting or 
 *			   user doesn't have permissions to write to, delete or
 *			   redefine the variable or just an error
 *		0 - successfully set environment variable (number bytes)
 */

#include <bootstd.h>
#include <errno.h>

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

static _bsc1 (int, setbenv, char *, a)

int bsc_setenv ( char *pair)
{
    char *tmpbuff;
    int countN = 0, countD = 0;
#if defined(BSC_SEMAPHORE_SUPPORT)
    int sid;
#endif
    if  ( !pair || (*pair == 0) )
	return -1;

    tmpbuff = pair;
    while ( *tmpbuff && (*tmpbuff != '=') ) {
	countN++;
	if  ( countN > MAX_ENVNAME_SIZE )
	    return -2;
	tmpbuff++;
	}
    if(*tmpbuff == '=') tmpbuff++;
    while ( *tmpbuff ) {
	countD++;
	if  ( countD > MAX_ENVDATA_SIZE )
	    return -3;
	tmpbuff++;
	}

#if defined(BSC_SEMAPHORE_SUPPORT)
    sid = bsc_sem_open();
    if  ( bsc_sem_lock(sid) ) {
	printf ("bsc_setenv: BSC_SEM locked ...\n");
	return -1;
	}
#endif

    if  ( setbenv(pair) ) {
#if defined(BSC_SEMAPHORE_SUPPORT)
	bsc_sem_unlock(sid);
#endif
        return -4;
	}
#if defined(BSC_SEMAPHORE_SUPPORT)
    bsc_sem_unlock(sid);
#endif
    
    return 0;
}

#else

int
bsc_setenv ( char *pair)
{
    int bscfd, ret = -1;
    bsc_op_t bset;
    char *tmpbuff;
    int countN = 0, countD = 0;

    if  ( !pair || (*pair == 0) )
	return ret;

    tmpbuff = pair;
    while ( *tmpbuff && (*tmpbuff != '=') ) {
	countN++;
	if  ( countN > MAX_ENVNAME_SIZE )
	    return -2;
	tmpbuff++;
	}
    if(*tmpbuff == '=') tmpbuff++;
    while ( *tmpbuff ) {
	countD++;
	if  ( countD > MAX_ENVDATA_SIZE )
	    return -3;
	tmpbuff++;
	}
    
    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return ret;

    bset.arg1 = strlen(pair)+1;
    bset.arg2 = pair;
    ret = ioctl(bscfd, __BN_setbenv, (void *)&bset);

    close (bscfd);
    return ret;

}

#endif
