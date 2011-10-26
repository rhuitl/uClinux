// $Id: fmtx-64.c,v 1.1 2004/06/16 10:06:03 ensc Exp $    --*- c -*--

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

#define FMT_BITSIZE	64
#include "fmtx.hc"

#if __WORDSIZE==FMT_BITSIZE
size_t	FMT_P(xulong)(char *ptr, unsigned long val) ALIASFUNC(xuint64);
size_t	FMT_P( xlong)(char *ptr,          long val) ALIASFUNC( xint64);
#endif
