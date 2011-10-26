/*
 * bsc_reset.c
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
#include <stdlib.h>
#include "bootstd.h"

char * tname = "bsc_reset";

int main(int argc, char * argv[])
{
	if(argc == 1){
		printf("Usage: %s [2|4|8]\n", argv[0]);
		printf("where:  2 -- for PGM_RESET_AFTER\n");    
		printf("        4 -- for PGM_EXEC_AFTER\n");    
		printf("        8 -- for PGM_HALT_AFTER\n");    
		return 0;
	}
	switch (atoi(argv[1])){
	case 2:
		printf("Reset the board now!\n");
		bsc_reset(PGM_RESET_AFTER);
		break;
	case 4:
		//PGM_EXEC_AFTER
		printf("Execute program in RAM!\n"); 
		bsc_reset(PGM_EXEC_AFTER);
		break;
	case 8:
		// PGM_HALT_AFTER
		printf("System will halt!\n"); 
		bsc_reset(PGM_HALT_AFTER);
		break;
	default:
		printf("This action is not supported.\n");
		break;
	}
	return 0;
}
