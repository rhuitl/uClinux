// $Id: antidos.c,v 1.4 2003/05/26 21:49:22 ensc Exp $    --*- c++ -*--

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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "antidos.h"
#include "parameters.h"

#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <sys/param.h>

struct Data
{
    struct in_addr	ip;
    time_t		access_time;
    unsigned int	counter;
};

static int
Data_searchCompare(void const *lhs_v, void const *rhs_v)
{
  struct in_addr const *	lhs = lhs_v;
  struct Data const *		rhs = rhs_v;
  assert(lhs!=0 && rhs!=0);

  if      (lhs->s_addr < rhs->ip.s_addr) return -1;
  else if (lhs->s_addr > rhs->ip.s_addr) return +1;
  else                                   return  0;
}

static int
Data_sortCompare(void const *lhs_v, void const *rhs_v)
{
  struct Data const *		lhs = lhs_v;
  assert(lhs!=0);

  return Data_searchCompare(&lhs->ip, rhs_v);
}

void
AntiDOS_init(AntiDOS *dos)
{
  assert(dos!=0);

  dos->min_time = 0;
  Vector_init(&dos->data, sizeof(struct Data));
}

unsigned int
AntiDOS_registerIP(AntiDOS *dos, struct in_addr const ip)
{
  time_t		t = time(0);
  struct Data *		data = Vector_search(&dos->data, &ip, Data_searchCompare);

  if (data==0) {
    data = Vector_insert(&dos->data, &ip, Data_searchCompare);
    assert(data!=0);

    data->ip          = ip;
    data->access_time = t;
    data->counter     = 1;
  }
  else {
    time_t		delta = t - data->access_time;

    data->access_time = t;

    if (delta>ANTIDOS_TIME_BASE) {
      data->counter = 1;
      dos->min_time = 0;
    }
    else if (data->counter <= ANTIDOS_COUNT_MAX) {
	// data->counter can not become negative by this operation because
	// delta/ANTIDOS_TIME_BASE<=1
      data->counter -= data->counter*delta/ANTIDOS_TIME_BASE;
      data->counter += 1;
    }
    else if (delta>1)
      data->counter  = ANTIDOS_COUNT_MAX;
  }

  return data->counter;
}

void
AntiDOS_update(AntiDOS *dos)
{
  time_t		t = time(0);
  assert(dos!=0);
  
  if (t-dos->min_time > ANTIDOS_TIME_BASE) {
    bool		was_changed = false;
    struct Data		*i;
    
    dos->min_time = t;
    for (i = Vector_begin(&dos->data); i!=Vector_end(&dos->data); ++i) {
      if (t - i->access_time>ANTIDOS_TIME_BASE) {
	i->ip.s_addr  = 0xFFFFFFFF;
	was_changed   = true;
      }
      else
	dos->min_time = MIN(dos->min_time, i->access_time);
    }

    if (was_changed) {
      Vector_sort(&dos->data, Data_sortCompare);
      for (i=Vector_end(&dos->data); i!=Vector_begin(&dos->data);) {
	--i;
	if (i->ip.s_addr!=0xFFFFFFFF) break;

	Vector_popback(&dos->data);
      }

      Vector_resize(&dos->data);
    }
  }
}

bool
AntiDOS_isOversized(AntiDOS *dos)
{
  return Vector_count(&dos->data) >= ANTIDOS_ENTRIES_MAX;
}
