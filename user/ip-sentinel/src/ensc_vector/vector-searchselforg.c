// $Id: vector-searchselforg.c,v 1.1 2005/03/17 14:47:21 ensc Exp $    --*- c -*--

// Copyright (C) 2005 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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
#include "vector-internal.h"

#include <string.h>
#include <assert.h>
#include <stdbool.h>

void *
Vector_searchSelfOrg(struct Vector *vec, void const *key,
		     int (*compare)(const void *, const void *),
		     VectorSelfOrgMethod method)
{
  char * const	start_ptr = vec->data;
  char * const	end_ptr   = start_ptr + vec->count*vec->elem_size;
  char		*ptr      = start_ptr;
  
  for (; ptr<end_ptr && compare(ptr, key)!=0; )
    ptr += vec->elem_size;

  if      (end_ptr  <= ptr) ptr = 0;
  else if (start_ptr < ptr) {
    char		tmp[vec->elem_size];
    memcpy(tmp, ptr, vec->elem_size);

    assert(ptr >= start_ptr+vec->elem_size);

    switch (method) {
      case vecMOVE_FRONT		:
	memmove(start_ptr+vec->elem_size, start_ptr, ptr - start_ptr);

	ptr = start_ptr;
	break;
	
      case vecSHIFT_ONCE		:
	memmove(ptr, ptr  - vec->elem_size, vec->elem_size);
	ptr -= vec->elem_size;
	break;

      default		:
	assert(false);
	ptr   = 0;
    }

    memcpy (ptr, tmp, vec->elem_size);
  }

  return ptr;
}

