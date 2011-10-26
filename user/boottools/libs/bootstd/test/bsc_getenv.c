/*
 * bsc_getenv.c     
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
char * tname = "bsc_getenv";
char tvalue[] = "V1";
char rvalue[32];

#define PRINTF 1

int main(int argc, char * argv[])
{
	int ret = 0;
	int err = 0;


	// case 1: set a valid string and then read back
	
	memset(pair, 0, sizeof(pair));
	strcat(pair, tname);
	strcat(pair, "=");
	strcat(pair, tvalue);
	ret = bsc_setenv(pair);

	if(ret != 0) {
#if PRINTF
		printf("setting %s failed: should return %d but return %d instead.\n", pair, 0, ret);
#endif
		err = 1;
	}
	else{
		// read back 
		ret = bsc_getenv(tname, rvalue, sizeof(rvalue));
		if ( ret > 0){
			if(strcmp(rvalue, tvalue) != 0){
#if PRINTF
				printf("getenv %s failed: should return %s but return %s instead.\n", tname, tvalue, rvalue);
#endif
				err = 1;
			}
		}
		else {
			err = 1;
#if PRINTF
			printf("getenv failed: %s not found.\n", tname);
#endif
		}
	}
	
	// case 2: get an invalid environment variable
	if(err) {
#if PRINTF
		printf("due to previous error, getenv test couldn't continnue.\n");
#endif
		return err;
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
		ret = bsc_getenv(tname, rvalue, sizeof(rvalue)); 
		if( ret > 0){ 
#if PRINTF
			printf("getenv failed: environment variable %s is set to \"%s.\", should be null\n", tname, rvalue);
#endif
			err = 1;
		} else if(ret < 0) {
#if PRINTF
			printf("getenv failed: error occurs during bsc_getenv call.");
#endif
			err = 1;
		}
	}
	return err;
}
