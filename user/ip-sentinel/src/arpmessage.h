// $Id: arpmessage.h,v 1.6 2004/12/23 00:44:18 ensc Exp $    --*- c++ -*--

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

#ifndef H_IPSENTINEL_ARPMESSAGE_H
#define H_IPSENTINEL_ARPMESSAGE_H

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include <features.h>    /* for the glibc version number */
#if (__GLIBC__ >= 2 && __GLIBC_MINOR >= 1) || defined(__dietlibc__)
#  include <netpacket/packet.h>
#  include <net/ethernet.h>     /* the L2 protocols */
#else
#  include <asm/types.h>
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>   /* The L2 protocols */
#endif

typedef struct
{
    struct ether_header         header;
    struct ether_arp            data;
    char                        padding[19];
} __attribute__ ((__packed__)) ArpMessage;


#endif	//  H_IPSENTINEL_ARPMESSAGE_H
