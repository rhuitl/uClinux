/*
 * debug.c
 *
 * $Id: debug.c,v 1.1 2006/02/13 09:58:08 andrzej Exp $
 *
 * Redboot Flash Configuration parser. 
 * Debug utilities. 
 *
 * Copyright (C) 2006 Ekiert sp z o.o.
 * Author: Andrzej Ekiert <a.ekiert@ekiert.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version. 
 */
#include <stdio.h>

#include "debug.h"

uint8_t verbosity = VERB_LOW;

void hex_dump(void *buf, uint16_t len)
{
	uint16_t i;
	for (i = 0 ; i < len; i++) {
		printf("%02x", ((uint8_t*)buf)[i]);
		if (i%2) {
			printf(" ");
		}
		if (15 == i%16) {
			printf("\n");
		}
	}
	printf("\n");
}

