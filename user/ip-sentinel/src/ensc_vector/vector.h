// $Id: vector.h,v 1.3 2005/03/17 14:47:53 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef H_UTILVSERVER_VECTOR_VECTOR_H
#define H_UTILVSERVER_VECTOR_VECTOR_H

#include <stdlib.h>

struct Vector
{
    void	*data;
    size_t	count;
    size_t	allocated;

    size_t	elem_size;
};

typedef enum { vecMOVE_FRONT, vecSHIFT_ONCE }		 VectorSelfOrgMethod;

void	Vector_init(struct Vector *, size_t elem_size);
void	Vector_free(struct Vector *);
void *	Vector_search(struct Vector *, void const *key, int (*compar)(const void *, const void *));
void *	Vector_searchSelfOrg(struct Vector *, void const *key,
			     int (*compar)(const void *, const void *),
			     VectorSelfOrgMethod method);
void	Vector_sort(struct Vector *, int (*compar)(const void *, const void *));
void	Vector_unique(struct Vector *, int (*compar)(const void *, const void *));
void *	Vector_pushback(struct Vector *);
void *	Vector_insert(struct Vector *, void const *key, int (*compar)(const void *, const void *));
void	Vector_popback(struct Vector *);
void	Vector_resize(struct Vector *vec);
void	Vector_clear(struct Vector *vec);
void	Vector_zeroEnd(struct Vector *vec);

static void const *	Vector_searchSelfOrg_const(struct Vector const *, void const *key,
						   int (*compar)(const void *, const void *),
						   VectorSelfOrgMethod method);
static void const *	Vector_search_const(struct Vector const *, void const *key, int (*compar)(const void *, const void *));
static void *		Vector_begin(struct Vector *);
static void *		Vector_end(struct Vector *);
static void const *	Vector_begin_const(struct Vector const *);
static void const *	Vector_end_const(struct Vector const *);
static size_t		Vector_count(struct Vector const *vec);

#include "vector.hc"

#endif	//  H_UTILVSERVER_VECTOR_VECTOR_H
