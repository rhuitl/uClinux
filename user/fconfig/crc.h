/*
 * crc.h
 *
 * $Id: crc.h,v 1.1 2006/02/13 09:58:08 andrzej Exp $
 *
 * Gary S. Brown's CRC - header. 
 *
 * Copyright (C) 2006 Ekiert sp z o.o.
 * Author: Andrzej Ekiert <a.ekiert@ekiert.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version. 
 */

#ifndef CRC_H
#define CRC_H

#include <stdint.h>

uint32_t crc32(uint8_t *s, uint32_t len);

#endif //CRC_H

