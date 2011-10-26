/* $Id$ */

/*
** Copyright (C) 2005 Sourcefire, Inc.
** AUTHOR: Steven Sturges
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* stream_ignore.h
 * 
 * Purpose: Handle hash table storage and lookups for ignoring
 *          entire data streams.
 *
 * Arguments:
 *   
 * Effect:
 *
 * Comments: Used by Stream4 & Stream5 -- don't delete too soon.
 *
 * Any comments?
 *
 */

#ifndef STREAM_IGNORE_H_
#define STREAM_IGNORE_H_

int IgnoreChannel(u_int32_t cliIP, u_int16_t cliPort,
                  u_int32_t srvIP, u_int16_t srvPort,
                  char protocol, char direction, char flags,
                  u_int32_t timeout);

char CheckIgnoreChannel(Packet *);

#endif /* STREAM_IGNORE_H_ */

