/*
 * bsc_printenv.c
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
 * format: 	int bsc_printenv(FILE *out, char *strname);
 *		fprint environment variable "name=value" if strname is
 *		substring of the name and starts from begining
 *
 * parameters:  substring to find or '*' to print all with a current pmask
 *		
 * returns:	0  - Ok
 *		-1 - on error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bootstd.h>

int
bsc_printenv(FILE *out, char *str)
{
    static char ValueB[1028];
    static char NameB[36];
    int ret=0;
#if defined(BSC_SEMAPHORE_SUPPORT)
    int sid;
#endif
    
    if  ( out == NULL || !str )
	return -1;

#if defined(BSC_SEMAPHORE_SUPPORT)
    sid = bsc_sem_open();
    if  ( bsc_sem_lock(sid) ) {
	printf ("bsc_printenv: BSC_SEM locked ...\n");
	return -1;
	}
#endif

    ret = (int)bsc_readenv(0, NameB, sizeof(NameB));
    while ( ret != 0 ) {
        if  (( str[0] == '*' ) || ((unsigned int)strstr( NameB, str) == (unsigned int)NameB)) {
	    bsc_readenv(2, ValueB, sizeof(ValueB));
	    fprintf(out, "%s=%s\n", NameB, ValueB);
	    }
	ret = (int)bsc_readenv(1, NameB, sizeof(NameB));
	}

#if defined(BSC_SEMAPHORE_SUPPORT)
    bsc_sem_unlock(sid);
#endif

    return 0; 
}
