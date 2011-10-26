/*
 * test_getenv.c
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

int main(int argc, char *argv[]) 
{
    static char ValueB[1028];
    if  ( argc != 2 ) {
	printf ("usage: %s <env_name>\n", argv[0]);
	return (-1);
	}
    bsc_getenv(argv[1], ValueB, sizeof(ValueB));
    printf("%s: %s=%s\n", argv[0], argv[1], ValueB);
    return(0); 
}
