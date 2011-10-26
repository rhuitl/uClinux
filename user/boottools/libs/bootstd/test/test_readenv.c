/*
 * test_readenv.c
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bootstd.h>

int 
main(int argc, char *argv[]) 
{
    static char ValueB[1028];
    static char NameB[36];
    char *pstr;
    int ret=0;

    if  ( argc != 2 ) {
	printf ("usage: %s < * | env_name_first_chars >\n", argv[0]);
	return (-1);
	}

    ret = (int)bsc_readenv(0, NameB, sizeof(NameB));
    while ( ret != 0 ) {
        if  ( argv[1][0] != '*' ) {
	    pstr = strstr( NameB, argv[1]);
	    if  ( (unsigned int)pstr !=  (unsigned int)NameB )
		goto next_env;
	    }
	bsc_readenv(2, ValueB, sizeof(ValueB));
	printf("%s=%s\n", NameB, ValueB);
next_env:
	ret = (int)bsc_readenv(1, NameB, sizeof(NameB));
	}

    return(0); 
}
