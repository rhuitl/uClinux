// $Id: prioqueue.c,v 1.4 2003/08/22 19:47:26 ensc Exp $    --*- c++ -*--

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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "prioqueue.h"
#include "wrappers.h"
#include "util.h"
#include <assert.h>

inline static size_t ALWAYSINLINE
powify(size_t val)
{
  int	i;

  for (i=sizeof(size_t)*8; i>0;) {
    --i;
    if (val&(1<<i)) {
	// overflow
      if (i==(sizeof(size_t)*8-1)) return val;
      else                         return (1<<(i+1))-1;
    }
  }

  return 1;
}

inline static size_t
parent(size_t i)
{
  assert(i>0);
  return (i-1)/2;
}

inline static size_t
left(size_t i)
{
  return 2*i + 1;
}

inline static size_t
right(size_t i)
{
  return 2*i + 2;
}

inline static void *
addr(void *base, size_t pos, size_t elem_size)
{
  return (char *)base + pos*elem_size;
}

void
PriorityQueue_init(struct PriorityQueue *q,
		   PriorityQueueCompareFunc cmp_func,
		   size_t count, size_t elem_size)
{
  assert(q!=0);
  assert(cmp_func!=0);
  assert(elem_size>0);

  count = powify(count);
  
  q->data      = Emalloc(count * elem_size);
  q->count     = 0;
  q->elem_size = elem_size;
  q->allocated = count;
  q->cmp_func  = cmp_func;
}

#ifdef ENSC_TESTSUITE
void
PriorityQueue_free(struct PriorityQueue *q)
{
  assert(q!=0);
  
  free(q->data);
#ifndef NDEBUG  
  q->count     = 0xdeadbeef;
  q->allocated = 0xdeadbeef;
  q->elem_size = 0xdeadbeef;
  q->data      = (void *)(0xdeadbeef);
#endif
}
#endif

static void
PriorityQueue_heapify(struct PriorityQueue *q, size_t pos)
{
  size_t		l = left(pos);
  size_t		r = right(pos);
  size_t		largest;

  void * const		ptr = q->data;
  size_t		c   = q->count;
  size_t		e   = q->elem_size;

  assert(q!=0);
  
  if (l<c && (*q->cmp_func)(addr(ptr, l, e), addr(ptr, r, e))>0)
    largest = l;
  else
    largest = pos;

  if (r<c && (*q->cmp_func)(addr(ptr, r, e), addr(ptr, largest, e))>0)
    largest = r;

  if (largest!=pos) {
    void	*aux = alloca(e);

    memcpy(aux, addr(ptr, pos, e), e);
    memcpy(addr(ptr, pos, e), addr(ptr, largest, e), e);
    memcpy(addr(ptr, largest, e), aux, e);

    PriorityQueue_heapify(q, largest);
  }
}

void
PriorityQueue_extract(struct PriorityQueue *q)
{
  assert(q!=0);

  if (q->count==0) return;

  --q->count;
  if (q->count>0) {
    size_t		e    = q->elem_size;

    memcpy(q->data, addr(q->data, q->count, e), e);
    PriorityQueue_heapify(q, 0);
  }
}


static void ALWAYSINLINE
PriorityQueue_insertInternal(struct PriorityQueue *q, void const *key)
{
  void * const		ptr = q->data;
  size_t		e   = q->elem_size;
  size_t		i   = q->count;

  for (i=q->count; i>0; i=parent(i)) {
    void *		aux = addr(ptr, parent(i), e);

    if ((*q->cmp_func)(aux, key) >= 0) break;
    memcpy(addr(ptr, i, e), aux, e);
  }

  memcpy(addr(ptr, i, e), key, e);
  ++q->count;
}

void
PriorityQueue_insert(struct PriorityQueue *q, void const *key)
{
  assert(q!=0);

  if (q->count==q->allocated) {
    size_t	new_size = q->allocated*2 + 1;
    if (new_size<q->allocated) {
      WRITE_MSG(2, "priority-queue exceeded space\n");
      exit(1);
    }
    q->allocated = new_size;
    q->data      = Erealloc(q->data, q->allocated * q->elem_size);
  }

  PriorityQueue_insertInternal(q, key);
}



#ifdef ENSC_TESTSUITE
void
PriorityQueue_test()
{
  assert(powify(0)==1);
  assert(powify(1)==1);
  assert(powify(2)==3);
  assert(powify(3)==3);
  assert(powify(4)==7);
  assert(powify(23)==31);
  assert(powify(64)==127);
  assert(powify(0x81234567)==0x81234567);

  assert(parent(7) ==3);
  assert(parent(9) ==4);
  assert(parent(10)==4);
  assert(parent(14)==6);

  assert(left (3)==7);
  assert(right(3)==8);  
  assert(left (6)==13);
  assert(right(6)==14);  
}

void
PriorityQueue_print(struct PriorityQueue const *q,
		    int fd,
		    void (*func)(int fd, void const*))
{
  char		*delim = "";
  size_t	i;
  
  assert(q!=0);
  assert(func!=0);
  
  WRITE_MSG(fd, "[");
  for (i=0; i<q->count; ++i) {
    WRITE_MSG(fd, delim);
    (*func)(fd, addr(q->data, i, q->elem_size));
    delim = ", ";
  }
  WRITE_MSG(fd, "] (");
  writeUInt(fd, q->count);
  WRITE_MSG(fd, ")\n");
}

#endif
