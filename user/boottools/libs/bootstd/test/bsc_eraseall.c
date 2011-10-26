/*
 * bsc_eraseall.c     
 * 
 * Testing bsc_eraseall by reading all environment variables then calling bsc_eraseall
 * after that restoring all the environment variables. Environment variables will be
 * displayed before and after the bsc_eraseall call.
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

char * tname = "bsc_eraseall";
#define MAXSIZE 128   /* hold 128 environment variables */
char pair[MAX_ENVPAIR_SIZE+4];

int main(int argc, char * argv[])
{
	int p = 0;
	int i = 0, num = 0;
	int ret;
	char varname[MAXSIZE][MAX_ENVNAME_SIZE+4], value[MAXSIZE][MAX_ENVDATA_SIZE+4];

	{
		i = 0;
	        printf("Before erasing...\n");
	        p = bsc_readenv(0, varname[i], sizeof(varname[i]));
	        while (p && i < MAXSIZE) {
	                bsc_readenv(2, value[i], sizeof(value[i]));
	                printf("%s=%s\n", varname[i], value[i]);
	                i++;
	                p = bsc_readenv(1, varname[i], sizeof(varname[i]));
	        }
		num = i;
	}
	bsc_eraseall();
	{
		char tmp_name[MAX_ENVNAME_SIZE+4], tmp_val[MAX_ENVDATA_SIZE+4];
		i = 0;
	        printf("After erasing...\n");
	        p = bsc_readenv(0, tmp_name, sizeof(tmp_name));
	        while (p) {
	                bsc_readenv(2, tmp_val, sizeof(tmp_val));
	                printf("%s=%s\n", tmp_name, tmp_val);
	                p = bsc_readenv(1, tmp_name, sizeof(tmp_name));
	        }
	}

	printf("Restoring...\n");
	for(i = 0; i < num; i++){
		memset(pair, 0, sizeof(pair));
        	strcat(pair, varname[i]);
        	strcat(pair, "=");
        	strcat(pair, value[i]);
        	ret = bsc_setenv(pair);
		if(ret) 
			printf("failed to restore %s\n", pair);
	}
	return 0;
}
