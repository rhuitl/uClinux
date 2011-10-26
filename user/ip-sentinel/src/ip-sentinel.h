// $Id: ip-sentinel.h,v 1.4 2003/08/22 14:39:48 ensc Exp $    --*- c++ -*--

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

#ifndef H_IPSENTINEL_IPSENTINEL_H
#define H_IPSENTINEL_IPSENTINEL_H

#include "parameters.h"

#include <stdbool.h>
#include <signal.h>

extern struct ether_addr	local_mac_address;

inline static bool
isDOS(unsigned int count)
{
  return ((count>ANTIDOS_COUNT_LOW && count<=ANTIDOS_COUNT_HIGH &&
	   (rand()%(ANTIDOS_COUNT_HIGH-ANTIDOS_COUNT_LOW)>=
	    (ANTIDOS_COUNT_HIGH-count))) ||
	  (count>ANTIDOS_COUNT_HIGH));
}

#endif	//  H_IPSENTINEL_IPSENTINEL_H
