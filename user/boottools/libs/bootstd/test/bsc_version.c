/*
 * bsc_version.c
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

char * tname = "bsc_version";

int main(int argc, char * argv[])
{
	int ret = 0;

	ret = bsc_version();

	printf("%s returned %d\n", tname, ret);

	return 0;
}
