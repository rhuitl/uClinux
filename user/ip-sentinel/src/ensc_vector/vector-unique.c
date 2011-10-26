// $Id: vector-unique.c,v 1.1 2004/02/06 14:47:18 ensc Exp $    --*- c -*--

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

#include "vector.h"

#include <assert.h>
#include <string.h>

  // TODO: do not iterate from begin to end but in the reverse direction. This should be more
  // effective.
void
Vector_unique(struct Vector *vec, int (*compare)(const void *, const void *))
{
  size_t		idx;
  
  if (vec->count<2) return;

  for (idx=0; idx+1<vec->count; ++idx) {
    char	*ptr      = (char *)(vec->data) + idx*vec->elem_size;
    char	*next_ptr = ptr + vec->elem_size;
    size_t	next_idx  = idx + 1;

    while (next_idx<vec->count &&
	   compare(ptr, next_ptr)==0) {
      ++next_idx;
      next_ptr += vec->elem_size;
    }

    if (next_idx==vec->count)
      vec->count = idx+1;
    else if (next_idx-idx > 1) {
      memmove(ptr + vec->elem_size,
	      next_ptr, (vec->count - next_idx)*vec->elem_size);
      vec->count -= (next_idx-idx-1);
    }
  }
}

