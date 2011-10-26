// $Id: list-searchselforg.c,v 1.1 2005/03/17 14:47:21 ensc Exp $    --*- c -*--

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
#include <stdbool.h>

void const *
List_searchSelfOrg(struct List const *list, void const *key,
		   int (*compare)(const void *, const void *),
		   ListSelfOrgMethod method)
{
  struct List		*list_v = (struct List *)(list);
  struct ListItem	**itm   = &list_v->root;

  switch (method) {
    case listMOVE_FRONT		:
      while (*itm!=0 && compare((*itm)->data, key)!=0)
	itm = &(*itm)->next;

      if (*itm && *itm!=list->root) {
	struct ListItem		*res = *itm;

	*itm         = res->next;
	res->next    = list->root;
	list_v->root = res;

	itm          = &list_v->root;
      }
      break;

    case listSHIFT_ONCE		:
      if (*itm!=0 && compare((*itm)->data, key)!=0) {
	while ((*itm)->next!=0 &&
	       compare((*itm)->next->data, key)!=0)
	  itm = &(*itm)->next;

	if ((*itm)->next==0)
	  itm = &(*itm)->next;
	else {
	  struct ListItem	*res = (*itm)->next;

	  (*itm)->next = res->next;
	  res->next    = *itm;
	  *itm         = res;
	}
      }
      break;

    default		:  assert(false); return 0;
  }

  if (*itm!=0) return (*itm)->data;
  else         return 0;  
}
