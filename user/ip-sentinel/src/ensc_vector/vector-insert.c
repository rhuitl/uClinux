// $Id: vector-insert.c,v 1.2 2004/02/06 16:42:56 ensc Exp $    --*- c -*--

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
#include <string.h>

void *
Vector_insert(struct Vector *vec, void const *key,
	      int (*compare)(const void *, const void *))
{
  char *	data;
  char *	end_ptr = Vector_pushback(vec);

  for (data=vec->data; data<end_ptr; data += vec->elem_size) {
    if (compare(key, data)<0) {
      memmove(data+vec->elem_size, data,
	      (char *)(end_ptr) - (char *)(data));
      return data;
    }
  }

  return end_ptr;
}
