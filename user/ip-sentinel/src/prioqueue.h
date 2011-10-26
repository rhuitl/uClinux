// $Id: prioqueue.h,v 1.1 2003/08/22 01:55:51 ensc Exp $    --*- c++ -*--

// Copyright (C) 2003 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef H_IPSENTINEL_PRIOQUEUE_H
#define H_IPSENTINEL_PRIOQUEUE_H

#include <stdlib.h>

typedef int (*PriorityQueueCompareFunc)(void const *, void const *);

struct PriorityQueue
{
    void			*data;
    size_t			count;
    size_t			allocated;
    size_t			elem_size;
    
    PriorityQueueCompareFunc	cmp_func;
};

void		PriorityQueue_init(struct PriorityQueue *,
				   PriorityQueueCompareFunc cmp_func,
				   size_t count, size_t elem_size);
void 		PriorityQueue_free(struct PriorityQueue *);

void		PriorityQueue_insert(struct PriorityQueue *, void const *key);
void		PriorityQueue_extract(struct PriorityQueue *);

static void const *	PriorityQueue_max(struct PriorityQueue const *);
static size_t		PriorityQueue_count(struct PriorityQueue const *q);

#ifdef ENSC_TESTSUITE
void			PriorityQueue_test();
void			PriorityQueue_print(struct PriorityQueue const *,
					    int fd, void (*func)(int, void const *));
#endif

#include "prioqueue.ic"

#endif	//  H_IPSENTINEL_PRIOQUEUE_H
