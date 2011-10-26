// $Id: prioqueue-check.c,v 1.3 2003/09/09 16:30:51 ensc Exp $    --*- c++ -*--

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
#include "util.h"
#include <unistd.h>
#include <assert.h>

struct ether_addr	local_mac_address = { { 127,0,0,1,0,0 } };

int cmp(void const *lhs_v, void const *rhs_v)
{
  unsigned int const *	lhs = lhs_v;
  unsigned int const *	rhs = rhs_v;

  assert(lhs!=0 && rhs!=0);

  return *lhs-*rhs;
}

void print(int fd, void const *data_v)
{
  unsigned int const *	data = data_v;

  assert(data!=0);
  writeUInt(fd, *data);
}

int main(int argc, char *argv[])
{
  struct PriorityQueue		q;
  int				i;
  
  PriorityQueue_test();
  PriorityQueue_init(&q, &cmp, 15, sizeof(unsigned int));

  for (i=1; i<argc; ++i) {
    if (argv[i][0]=='e') {
      void const	*x = PriorityQueue_max(&q);

      if (x==0) WRITE_MSG(1, "<null>");
      else      print(1, x);

      WRITE_MSG(1, " <- ");
      PriorityQueue_extract(&q);
    }
    else {
      unsigned int	x = atoi(argv[i]);
      PriorityQueue_insert(&q, &x);
    }

    PriorityQueue_print(&q, 1, print);
  }

  PriorityQueue_free(&q);
  
  return 0;
}
