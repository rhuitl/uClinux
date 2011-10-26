// $Id: fmtx.hc,v 1.1 2004/06/16 10:06:03 ensc Exp $    --*- c -*--

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

#include "fmt.h"
#include "fmt-internal.h"
#include <string.h>

#define STRINGIFY_(X)	#X
#define STRINGIFY(X)	STRINGIFY_(X)
#define ALIASFUNC(X)	__attribute__((__alias__(STRINGIFY(FMT_P(X)))))


size_t
CONCAT(FMT_P(xuint),)(char *ptr, CONCAT(uint_least,_t) val)
{
  FMT_FN(16,8);
}

size_t
CONCAT(FMT_P(xint),)(char *ptr,
		     CONCAT(int_least,_t) val)
{
  size_t	offset=0;
  if (val<0) {
    val      = -val;
    offset   = 1;

    if (ptr!=0)
      *ptr++ = '-';
  }

  return CONCAT(FMT_P(xuint),)(ptr, val) + offset;
}
