/*
 * debug.h
 *
 * $Id: debug.h,v 1.1 2006/02/13 09:58:08 andrzej Exp $
 *
 * Redboot Flash Configuration parser. 
 * Debug utilities - header. 
 *
 * Copyright (C) 2006 Ekiert sp z o.o.
 * Author: Andrzej Ekiert <a.ekiert@ekiert.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version. 
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdint.h>

#define VERB_LOW 1
#define VERB_NORMAL 2
#define VERB_HIGH 3

extern uint8_t verbosity;

void hex_dump(void *buf, uint16_t len);

#define MESSAGE(verb, args...) \
	do { \
		if (verb <= verbosity) { \
			printf(args); \
		} \
	} while (0);

#endif //DEBUG_H

