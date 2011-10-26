// $Id: list.h,v 1.1 2005/03/17 14:47:21 ensc Exp $    --*- c -*--

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

#ifndef H_UTILVSERVER_VECTOR_LIST_H
#define H_UTILVSERVER_VECTOR_LIST_H

#include <stdlib.h>

struct ListItem;
struct List
{
    struct ListItem	*root;
    size_t		count;
    size_t		elem_size;
};

typedef enum { listMOVE_FRONT, listSHIFT_ONCE }		 ListSelfOrgMethod;

void	List_init(struct List *, size_t elem_size);
void	List_free(struct List *);
void *	List_add(struct List *, void const *key);
void *		List_at(struct List *, size_t idx);
void const *	List_at_const(struct List const *, size_t idx);

void const *	List_search(struct List const *, void const *key,
			    int (*compare)(const void *, const void *));

void const *	List_searchSelfOrg(struct List const *, void const *key,
				   int (*compare)(const void *, const void *),
				   ListSelfOrgMethod method);

#endif	//  H_UTILVSERVER_VECTOR_LIST_H
