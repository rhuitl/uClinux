// $Id: list-free.c,v 1.2 2005/03/19 02:03:30 ensc Exp $    --*- c -*--

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

void
List_free(struct List *list)
{
  struct ListItem 	*itm;

  for (itm = list->root; itm!=0; /* noop */)
  {
    struct ListItem	*next = itm->next;

    free(itm->data);
#ifndef NDEBUG
    itm->data = (void *)(0xdeadbeaf);
#endif
    free(itm);

    itm = next;
  }
}
