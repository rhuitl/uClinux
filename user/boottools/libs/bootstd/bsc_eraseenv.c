/*
 * bsc_eraseenv.c
 *
 * Copyright (c) 2006,2007  Arcturus Networks Inc.
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
 * format: 	int bsc_eraseenv(char *strname);
 *		erase environment variable "name" if strname is
 *		substring of the name and starts from begining
 *
 * parameters:  substring or '*' to erase all with a current pmask
 *		
 * returns:	negative number - error
 *		0 - Ok
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bootstd.h>

int bsc_eraseenv(char *name)
{
	char tmpname[MAX_ENVNAME_SIZE + 4];

	int ret = 0, rmgroup = 0;

	if (!name || (*name == 0))
		return ret;

	if (*name == '*')
		rmgroup = 2;
	else {
		char *pname = name;
		while (*pname++)	/* check for group remove */
			if (*pname == '*' && *(pname + 1) == 0) {
				rmgroup = 1;
				*pname = 0;
			}
	}

	switch (rmgroup) {
	default:		/* single erase */
	case 0:
		ret = bsc_setenv(name);
		break;

	case 1:
		ret = bsc_readenv(0, tmpname, MAX_ENVNAME_SIZE);
		while (ret > 0) {
			if ((unsigned int)strstr(tmpname, name) ==
			    (unsigned int)tmpname)
				if ((ret = bsc_setenv(tmpname)) != 0 )
					break;
			ret = bsc_readenv(1, tmpname, MAX_ENVNAME_SIZE);
		}
		break;

	case 2:
		ret = bsc_readenv(0, tmpname, MAX_ENVNAME_SIZE);
		while (ret > 0) {
#if 0
			if (ret = bsc_setenv(tmpname))
				break;
#endif
			ret = bsc_readenv(1, tmpname, MAX_ENVNAME_SIZE);
		}
		break;
	}
	return ret;
}
