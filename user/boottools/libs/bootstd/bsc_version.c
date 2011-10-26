/*
 * bsc_version.c
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
 * format: 	int *bsc_version(void);
 *		return the integer value of FW_VERSION environment var
 *
 * parameters:  none
 *
 * returns:	firmware version
 *		0 - if the version is not found/exist
 */

#include "bootstd.h"

int
bsc_version(void)
{
    int ver;
    int result = 0;
    int i = 0;
    char name[] = "FW_VERSION";

    char tmp[12];
    ver = bsc_getenv(name, tmp, sizeof(tmp));
    if  ( ver > 0 )
	while (tmp[i]) {
	    result = result*10 + (tmp[i++] - '0');
	    }
    return result;
}
