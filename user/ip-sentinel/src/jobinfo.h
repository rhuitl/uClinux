// $Id: jobinfo.h,v 1.2 2003/10/07 17:21:20 ensc Exp $    --*- c++ -*--

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

#ifndef H_IPSENTINEL_JOBINFO_H
#define H_IPSENTINEL_JOBINFO_H

#include "arpmessage.h"

struct ScheduleInfo
{
    time_t		schedule_time;
    ArpMessage		message;
    struct sockaddr_ll	address;
};

struct RequestInfo
{
    struct ether_arp		request;
    struct ether_addr		mac;
    enum { jobSRC, jobDST }	type;
    struct {
	bool			f;
	struct ether_addr	v;
    }				poison_mac;
};

#endif	//  H_IPSENTINEL_JOBINFO_H
