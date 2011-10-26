// $Id: list-add.c,v 1.1 2005/03/17 14:47:21 ensc Exp $    --*- c -*--

// Copyright (C) 2005 Enrico Scholz <enrico.scholz@sigma-chemnitz.de>
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
//  

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "list.h"
#include "list-internal.h"


void *
List_add(struct List *list, void const *data)
{
  return List_insertInternal(list, data, &list->root, 0)->data;
}
