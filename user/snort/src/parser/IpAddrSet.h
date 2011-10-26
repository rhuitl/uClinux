/* $Id$ */
/*
 * Copyright(C) 2002 Sourcefire, Inc.
 *
 * Author(s):  Andrew R. Baker <andrewb@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef __IP_ADDR_SET_H__
#define __IP_ADDR_SET_H__

#include <sys/types.h>

typedef struct _IpAddrSet
{
    u_int32_t ip_addr;   /* IP addr */
    u_int32_t netmask;   /* netmask */
    u_int8_t  addr_flags; /* flag for normal/exception processing */

    struct _IpAddrSet *next;
} IpAddrSet;

/* flags */
#define EXCEPT_IP   0x01

void IpAddrSetPrint(char *prefix, IpAddrSet *);
void IpAddrSetDestroy(IpAddrSet *);
IpAddrSet *IpAddrSetCopy(IpAddrSet *);
IpAddrSet *IpAddrSetCreate();
IpAddrSet *IpAddrSetParse(char *);
int IpAddrSetContains(IpAddrSet *, struct in_addr);


/* XXX legacy support function */
int ParseIP(char *paddr, IpAddrSet *);

#endif /* __IP_ADDR_SET_H__ */
