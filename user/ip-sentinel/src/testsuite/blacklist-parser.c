// $Id: blacklist-parser.c,v 1.5 2004/12/23 00:44:18 ensc Exp $    --*- c++ -*--

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

#include "blacklist.h"
#include "arguments.h"
#include <signal.h>

struct ether_addr	local_mac_address = { { 127,0,0,1,0,0 } };

int main(int argc, char *argv[])
{
  struct Arguments	args = {
    .mac = { .type  = mcRANDOM },
    .ipfile    = argv[1]
  };
  BlackList		lst;

  if (argc!=2) return EXIT_FAILURE;
  
  BlackList_init(&lst, &args);
  BlackList_softUpdate(&lst);
  BlackList_print(&lst,1);

  BlackList_free(&lst);

  return EXIT_SUCCESS;
}


  /// Local Variables:
  /// compile-command: "make -C .. check"
  /// End:
