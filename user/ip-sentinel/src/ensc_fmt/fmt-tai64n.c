// $Id: fmt-tai64n.c,v 1.1 2004/06/16 10:06:03 ensc Exp $    --*- c -*--

// Copyright (C) 2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#include <sys/time.h>
#include <string.h>
#include <assert.h>

size_t
FMT_P(tai64n)(char *buf, struct timeval const *now)
{
  uint64_t		tai_secs = 1ll << 62;
  char *		ptr = buf;
  size_t		l;
  
  tai_secs += now->tv_sec;
  *ptr++ = '@';

  l = FMT_P(xuint64)(ptr, tai_secs);	// always 16 bytes
  assert(l==16);
  ptr +=  16;

  memset(ptr, '0', 8);
  l = FMT_P(xuint32)(0,   now->tv_usec*1000);
  FMT_P(xuint32)(ptr+8-l, now->tv_usec*1000);

  ptr +=  8;

  return ptr-buf;
}
