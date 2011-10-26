// $Id: fmt-32.c,v 1.1 2004/06/16 10:06:03 ensc Exp $    --*- c -*--

// Copyright (C) 2003 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#define FMT_BITSIZE	32
#include "fmt.hc"

#if __WORDSIZE==FMT_BITSIZE
size_t	FMT_P(ulong_base)(char *ptr, unsigned long val, char base) ALIASFUNC(uint32_base);
size_t	FMT_P( long_base)(char *ptr,          long val, char base) ALIASFUNC( int32_base);
#endif

size_t	FMT_P(uint_base)(char *ptr, unsigned int val, char base)   ALIASFUNC(uint32_base);
size_t	FMT_P( int_base)(char *ptr,          int val, char base)   ALIASFUNC( int32_base);
