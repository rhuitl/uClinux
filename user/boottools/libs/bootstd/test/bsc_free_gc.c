/*
 * bsc_free_gc.c     
 * 
 * Testing bsc_free and bsc_gc by writing an new environment variable, overwritten it
 * and remove it to see if the free space changes accordingly.
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

char * tname = "bsc_free_gc";
char * test_string1 = "string_length=17";
char * test_string2 = "string_length";
char * test_string3 = "string_length=18";

#define PRINTF 1

int main(int argc, char * argv[])
{

	int old_size, new_size, diff;
	int ret, err = 0;
	
	// clean up first
	bsc_setenv(test_string2);
	old_size = bsc_gc();

	ret = bsc_setenv(test_string1);
	if((new_size = bsc_free()) != bsc_gc()){
#if PRINTF
		printf("failed: after calling bsc_gc and bsc_setenv, calling bsc_free and bsc_gc gives different values\n");
#endif
		err = 1;
		return err;
	}

	diff = old_size - new_size;

	if(diff == 0 && ret == 0) {// should not happen
#if PRINTF
		printf("failed: the free environment variable space is not changed after successfully writing an environment variable\n");
#endif
		err = 1;
		return err;
	}
	// overwritten the same test string 
	bsc_setenv(test_string3);
	if(bsc_gc() != new_size){
#if PRINTF
		printf("failed: overwritten same string couldn't maintain the same environment variable space.\n");
#endif
		err = 1;
		return err;
	}

	// remove the test string
	bsc_setenv(test_string2);
	new_size = bsc_gc();
	if(new_size != old_size){
#if PRINTF
		printf("failed: removing the test string didn't free the environment variable space after calling bsc_gc.\n");
#endif
		err = 1;
		return err;
	}

	return 0;
}
