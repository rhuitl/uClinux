/*
 * bsc_gethwaddr.c     
 * 
 * Copyright (c) 2006  Arcturus Networks Inc.
 *      by Mingqiang Wu <www.ArcturusNetworks.com>
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

#include <string.h>
#include <stdio.h>
#include "bootstd.h"

char * tname = "bsc_gethwaddr";
#define devnum 2

char rvalue[32];

int main(int argc, char * argv[])
{
	int i = 0;
	unsigned char *p;

	for(i = 0; i < devnum; i++){
		p = (unsigned char *) bsc_gethwaddr(i, rvalue);
		printf("%s returned MAC: %02x:%02x:%02x:%02x:%02x:%02x for eth%d\n", tname, p[0], p[1], p[2], p[3], p[4], p[5], i);
	}
	return 0;
}
