/*
 *  util.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005 Sourcefire Inc.
 *
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef WIN32

#define snprintf _snprintf

#else

#include <sys/types.h>

typedef unsigned long long UINT64;

#endif



void *xmalloc(size_t byteSize);
char *xstrdup(const char *str);
void  xshowmem();
void  xfree( void * );

#endif
