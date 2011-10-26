// $Id: list-insertinternal.c,v 1.1 2005/03/17 14:47:21 ensc Exp $    --*- c -*--

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

#include <assert.h>
#include <string.h>

#define ENSC_WRAPPERS_STDLIB 1
#include <wrappers.h>

struct ListItem *
List_insertInternal(struct List *list, void const *data,
		    struct ListItem **before_pos,
		    struct ListItem *after_pos)
{
  struct ListItem	*item = Emalloc(sizeof(struct ListItem));

  assert((before_pos!=0 || after_pos!=0) &&
	 (before_pos==0 || after_pos==0));
  
  item->data = Emalloc(list->elem_size);
  memcpy(item->data, data, list->elem_size);

  if (before_pos!=0) {
    item->next  = *before_pos;
    *before_pos = item;
  }
  else {
    item->next      = after_pos->next;
    after_pos->next = item;
  }

  ++list->count;

  return item;
}
