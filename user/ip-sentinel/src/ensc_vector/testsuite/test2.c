// $Id: test2.c,v 1.2 2005/03/24 12:41:27 ensc Exp $    --*- c -*--

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

#undef NDEBUG

#include "ensc_vector/list.h"
#include "ensc_vector/list-internal.h"

#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

int	wrapper_exit_code = 2;

static int
cmp(void const *lhs_v, void const *rhs_v)
{
  int const * const	lhs = lhs_v;
  int const * const	rhs = rhs_v;

  return *lhs - *rhs;
}

struct List		l;


static void	A(int val)
{
  int *		res = List_add(&l, &val);

  assert(*res == val);
}

static int const *	S(int val)
{
  return List_search(&l, &val, cmp);
}

static int const *	SSO_F(int val)
{
  return List_searchSelfOrg(&l, &val, cmp, listMOVE_FRONT);
}

static int const *	SSO_S(int val)
{
  return List_searchSelfOrg(&l, &val, cmp, listSHIFT_ONCE);
}

static int 		P(size_t idx)
{
  int const	*res = List_at_const(&l, idx);

  assert(res!=0);
  return *res;
}

static bool		P0(size_t idx)
{
  return List_at_const(&l, idx) == 0;
}

static bool		CMP(int const *lhs, int rhs)
{
  return (lhs!=0 && *lhs==rhs) || (lhs==0 && rhs==-1);
}


int main()
{
  List_init(&l, sizeof(int));

  A(5); A(4); A(3); A(2); A(1); A(0);
  assert(P(0)==0 && P(1)==1 && P(2)==2 && P(3)==3 && P(4)==4 && P(5)==5 && P0(6));

  assert(CMP(S(5), 5) && CMP(S(2), 2) && CMP(S(0), 0));
  assert(CMP(S(42),-1));

  assert(CMP(SSO_F(5), 5));
  assert(P(0)==5 && P(1)==0 && P(2)==1 && P(3)==2 && P(4)==3 && P(5)==4 && P0(6));

  assert(CMP(SSO_F(5), 5));
  assert(P(0)==5 && P(1)==0 && P(2)==1 && P(3)==2 && P(4)==3 && P(5)==4 && P0(6));

  assert(CMP(SSO_F(0), 0));
  assert(P(0)==0 && P(1)==5 && P(2)==1 && P(3)==2 && P(4)==3 && P(5)==4 && P0(6));

  assert(CMP(SSO_F(4), 4));
  assert(P(0)==4 && P(1)==0 && P(2)==5 && P(3)==1 && P(4)==2 && P(5)==3 && P0(6));

  assert(CMP(SSO_F(5), 5));
  assert(P(0)==5 && P(1)==4 && P(2)==0 && P(3)==1 && P(4)==2 && P(5)==3 && P0(6));
  
  assert(CMP(SSO_F(42),-1));
  assert(P(0)==5 && P(1)==4 && P(2)==0 && P(3)==1 && P(4)==2 && P(5)==3 && P0(6));


  
  assert(CMP(SSO_S(3), 3));
  assert(P(0)==5 && P(1)==4 && P(2)==0 && P(3)==1 && P(4)==3 && P(5)==2 && P0(6));
  
  assert(CMP(SSO_S(3), 3));
  assert(P(0)==5 && P(1)==4 && P(2)==0 && P(3)==3 && P(4)==1 && P(5)==2 && P0(6));

  assert(CMP(SSO_S(5), 5));
  assert(P(0)==5 && P(1)==4 && P(2)==0 && P(3)==3 && P(4)==1 && P(5)==2 && P0(6));

  assert(CMP(SSO_S(4), 4));
  assert(P(0)==4 && P(1)==5 && P(2)==0 && P(3)==3 && P(4)==1 && P(5)==2 && P0(6));

  assert(CMP(SSO_S(0), 0));
  assert(P(0)==4 && P(1)==0 && P(2)==5 && P(3)==3 && P(4)==1 && P(5)==2 && P0(6));

  assert(CMP(SSO_S(0), 0));
  assert(P(0)==0 && P(1)==4 && P(2)==5 && P(3)==3 && P(4)==1 && P(5)==2 && P0(6));

  assert(CMP(SSO_S(0), 0));
  assert(P(0)==0 && P(1)==4 && P(2)==5 && P(3)==3 && P(4)==1 && P(5)==2 && P0(6));
  
  assert(CMP(SSO_S(42), -1));
  assert(P(0)==0 && P(1)==4 && P(2)==5 && P(3)==3 && P(4)==1 && P(5)==2 && P0(6));

  List_free(&l);

  return EXIT_SUCCESS;
}
