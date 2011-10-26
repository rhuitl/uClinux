// $Id: vector-zeroend.c,v 1.1 2004/06/16 10:10:55 ensc Exp $    --*- c -*--

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


void
Vector_zeroEnd(struct Vector *vec)
{
  void *	tmp;

  if (vec->allocated <= vec->count) {
    tmp = Vector_pushback(vec);
    Vector_popback(vec);
  }
  else
    tmp = Vector_end(vec);

  memset(tmp, 0, vec->elem_size);
}
