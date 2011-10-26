/*
 * bsc_setenv.c
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

char pair[32];
char *tname = "bsc_setenv";
char *tvalue = "V1";
char rvalue[32];

#define PRINTF 1

int main(int argc, char * argv[])
{
	int ret = 0;
	char * p;
	int err = 0;

	// case 1: Null string
	ret = bsc_setenv(NULL);

	if(ret != -1)
		printf("%s NULL string failed: should return %d but return %d instead.\n", tname, -1, ret);

	// case 2: set a valid string
	memset(pair, 0, sizeof(pair));
	strcat(pair, tname);
	strcat(pair, "=");
	p = strcat(pair, tvalue);

	ret = bsc_setenv(pair);

	if(ret != 0) {
#if PRINTF
		printf("%s %s failed: should return %d but return %d instead.\n", tname, pair, 0, ret);
#endif
		err = 1;
	}
	else{
		// read back 
		ret = bsc_getenv(tname, rvalue, sizeof(rvalue));

		if ( ret > 0 ){
			if(strcmp(rvalue, tvalue) != 0){
#if PRINTF
				printf("%s %s failed: should return %s but return %s instead.\n", tname, pair, tvalue, rvalue);
#endif
				err = 1;
			}
		}
		else {
			err = 1;
#if PRINTF
			if(ret == 0)
				printf("%s %s failed: %s not found.\n", tname, pair, tname);
			else
				printf("%s %s failed: error occurs during the bsc_setenv call.\n", tname, pair);
#endif
		}
	}
	// case 3: erase an environment variable
	if(err){
#if PRINTF
		printf("due to previous error, erasing %s couldn't be done.\n", tname);
#endif
	}
	else {
		memset(pair, 0, sizeof(pair));
		strcat(pair, tname);
		ret = bsc_setenv(pair);
		if(ret != 0) {
#if PRINTF
			 printf("removing %s failed: should return %d but return %d instead.\n", pair, 0, ret);
#endif
		}
		if(bsc_getenv(tname, rvalue, sizeof(rvalue))){ 
#if PRINTF
			printf(" failed: environment variable bsc_setenv is set to %s, should be null.\n", rvalue);
#endif
			err = 1;
		}
	}
	return err;
}
