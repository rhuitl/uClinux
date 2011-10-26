// $Id: vector.hc,v 1.2 2005/03/17 14:47:53 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

static inline UNUSED void *
Vector_begin(struct Vector *vec)
{
  return vec->data;
}

static inline UNUSED void *
Vector_end(struct Vector *vec)
{
  return (char *)(vec->data) + (vec->count * vec->elem_size);
}

static inline UNUSED void const *
Vector_begin_const(struct Vector const *vec)
{
  return vec->data;
}

static inline UNUSED void const *
Vector_end_const(struct Vector const *vec)
{
  return (char *)(vec->data) + (vec->count * vec->elem_size);
}

static inline UNUSED size_t
Vector_count(struct Vector const *vec)
{
  return vec->count;
}

static inline UNUSED void const *
Vector_search_const(struct Vector const *vec, void const *key, int (*compar)(const void *, const void *))
{
  return Vector_search((struct Vector *)(vec), key, compar);
}

static inline UNUSED void const *
Vector_searchSelfOrg_const(struct Vector const *vec, void const *key,
			   int (*compare)(const void *, const void *),
			   VectorSelfOrgMethod method)
{
  return Vector_searchSelfOrg((struct Vector *)(vec), key, compare, method);
}
