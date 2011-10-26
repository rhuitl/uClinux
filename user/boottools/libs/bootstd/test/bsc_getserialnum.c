/*
 * bsc_getserialnum.c 
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

char * tname="bsc_getserial";
char rvalue[32];

int main(int argc, char * argv[])
{
	char *p;

	p = bsc_getserialnum(rvalue);

	if(p)
		printf("%s returned %s\n", tname, rvalue);
	else
		printf("%s: no serial number is found\n", tname);

	return 0;
}
