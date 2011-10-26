/*
 * bsc_setpmask.c
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

/*================== copied from bootloader include/env.h ============================*/
#define FEF_WEAK        0x0001  /* Can be redefine */

#define FEF_BOOT_MASK   0x000E  /* Mask bits of bootloader */
#define FEF_BOOT_READ   0x0002  /* Read permission for bootloader */
#define FEF_BOOT_WRITE  0x0004  /* Write permission for bootloader */
#define FEF_BOOT_WHITE  0x0008  /* */

#define FEF_SUPER_MASK  0x00E0  /* Mask bits for supervisor */
#define FEF_SUPER_READ  0x0020  /* Read permission for supervisor */
#define FEF_SUPER_WRITE 0x0040  /* Write permission for supervisor */
#define FEF_SUPER_WHITE 0x0080

#define FEF_USER_MASK   0x0E00  /* Mask bits for user */
#define FEF_USER_READ   0x0200  /* Read permission for user */
#define FEF_USER_WRITE  0x0400  /* Write permission for user */
#define FEF_USER_WHITE  0x0800

#define FEF_FACTORY     0x1000  /* Factory defined variable */
#define FEF_SERIAL      0x2000

#define FEV_VALID       0xffffffffUL    /* Valid environment variable */
#define FEV_WHITEOUT    0x0000          /* Invalid, deleted environment variable */
#define FEV_PROTECT     0x0001          /* Cannot be deleted or redefined */

char * tname = "bsc_setpmask";

int main(int argc, char * argv[])
{
	char value[32];
	int p = 0;
	//FIXME: add more tests 
	// FLASH0_BASE is not readable if read permission is not set
	p = bsc_getenv("FLASH0_BASE", value, sizeof(value));
	if(p > 0){
		printf("FLASH0_BASE is readable, testing cannot continue.\n");
		return 1;
	}
	// set to read only permission
	bsc_setpmask(FEF_USER_READ | FEF_BOOT_READ | FEF_SUPER_READ);
	p = bsc_getenv("FLASH0_BASE", value, sizeof(value));
	if(p <= 0){
		printf("bsc_setpmask failed: FLASH0_BASE is not readable even though set to read permission.\n");
		return 1;
	}

	return 0;
}
