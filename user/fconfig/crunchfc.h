/*
 * crunchfc.h
 *
 * $Id: crunchfc.h,v 1.1 2006/02/13 09:58:08 andrzej Exp $
 *
 * Redboot Flash Configuration parser. 
 * Configuration parsing routines - header. 
 *
 * Copyright (C) 2006 Ekiert sp z o.o.
 * Author: Andrzej Ekiert <a.ekiert@ekiert.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version. 
 */

#ifndef CRUNCHFC_H
#define CRUNCHFC_H

#include <stdint.h>

struct config_data {
	int fd;
	uint32_t maxlen;
	uint32_t reallen;
	uint8_t swab;
	uint8_t *buf;
};

int8_t verify_fconfig(struct config_data *data);
int8_t get_key_value(struct config_data *data, uint8_t *nickname);
int8_t set_key_value(struct config_data *data, uint8_t *nickname, void *value);
void recalculate_crc(struct config_data *data);

#endif //CRUNCHFC_H

