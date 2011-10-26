/*
 * bsc_getenv.c
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
 * format: 	int bsc_getenv(char *name, char *buff, int buffsize);
 *
 * parameters:  name - the name of the environment variable to find
 *		buff - prealocated space for returned value
 *		bufsize - sizeof(buff)
 *
 * returns:	environment variable size 		or
 *		 0 - environment var is not found 	or
 *		-1 - on error
 */

#include <string.h>
#include <bootstd.h>
#include <errno.h>

#if !defined(KERNEL_BSC_IOCTL_SUPPORT)

#if BSC_MMU

static _bsc2(char *, getbenv, char *, a1, char *, a2)

int
bsc_getenv( char *name, char *buff, int buffsize)
{
    char tmpname[MAX_ENVNAME_SIZE];
    char tmpval [MAX_ENVDATA_SIZE];
    int  tmplen, ret = -1;

    if  ( !name || !buff )
	return ret;
    
    tmplen = strlen(name) + 1;	/* 1 for zero symbol */
    if  ((tmplen >= MAX_ENVNAME_SIZE) || (tmplen < 2) || (buffsize < 1))
	return ret;

    memset ( tmpname, 0, MAX_ENVNAME_SIZE );
    memcpy ( tmpname, name, tmplen );
    memset ( tmpval,  0, MAX_ENVDATA_SIZE );
    
#if defined(BSC_SEMAPHORE_SUPPORT)
    {
    int sid;
    sid = bsc_sem_open();
    if  ( bsc_sem_lock(sid) ) {
	printf ("bsc_printenv: BSC_SEM locked ...\n");
	return -1;
	}
#endif

    ret = (int)getbenv(tmpname, tmpval );

#if defined(BSC_SEMAPHORE_SUPPORT)
    bsc_sem_unlock(sid);
    }
#endif
    if  ( ret > 0 ) {
	tmplen = strlen(tmpval);
	if  ( tmplen >= buffsize )
	    return -1;
	memcpy ( buff, tmpval, tmplen );
	buff[tmplen] = 0;
	}

    return ret;
}

#else

static _bsc1(char *, getbenv, char *, a1)

int
bsc_getenv(char *name, char *buff, int buffsize)
{
    char *src;
    char *dst = buff;
    
#if defined(BSC_SEMAPHORE_SUPPORT)
    int sid;
    sid = bsc_sem_open();
    if  ( bsc_sem_lock(sid) ) {
	printf ("bsc_printenv: BSC_SEM locked ...\n");
	return -1;
	}
#endif

    src = getbenv(name);

#if defined(BSC_SEMAPHORE_SUPPORT)
    bsc_sem_unlock(sid);
#endif

    
    if ( (unsigned int) src != 0 ) {
        while ( *src )	*dst++ = *src++;
	*dst = 0;
	return ((unsigned int)dst-(unsigned int)buff);
	}
    return 0;
}

#endif

#else

int
bsc_getenv( char *name, char *buff, int buffsize)
{	
    int tmplen, ret = -1;
    int bscfd;
    bsc_op_t bget;

    if  ( !name || (*name == 0) || !buff )
	return ret;

    tmplen = strlen(name) + 1;	/* 1 for zero symbol */
    
    if  ((tmplen >= MAX_ENVNAME_SIZE) || (tmplen < 2) || (buffsize < 2))
	return ret;

    if	( (bscfd = open("/dev/bios", O_RDWR)) == -1 )
	return ret;

    bget.arg1 = tmplen;
    bget.arg2 = name;
    bget.arg3 = buffsize;
    bget.arg4 = buff;
    ret = ioctl(bscfd, __BN_getbenv, (void *)&bget);

    close(bscfd);

    return ret;

}

#endif /* KERNEL_BSC_IOCTL_SUPPORT */
