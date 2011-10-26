/*
 * test_gethwaddr.c
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
main(int argc, char * argv[])
{
    unsigned char hwaddr[6];

    if  ( bsc_gethwaddr(0, hwaddr) )
	printf("eth0: HWaddr %02x:%02x:%02x:%02x:%02x:%02x\n", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    else
	printf("Error\n");
    return 0;
}
