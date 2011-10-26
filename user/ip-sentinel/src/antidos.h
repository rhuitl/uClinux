// $Id: antidos.h,v 1.5 2004/12/23 00:44:18 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef H_IPSENTINEL_ANTIDOS_H
#define H_IPSENTINEL_ANTIDOS_H

#include "ensc_vector/vector.h"

#include <stdbool.h>
#include <netinet/in.h>

typedef struct
{
    time_t		min_time;
    struct Vector	data;
} AntiDOS;

void		AntiDOS_init(AntiDOS *);
unsigned int	AntiDOS_registerIP(AntiDOS *, struct in_addr const);
void		AntiDOS_update(AntiDOS *);
bool		AntiDOS_isOversized(AntiDOS *);

#endif	//  H_IPSENTINEL_ANTIDOS_H
