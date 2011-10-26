/* $Id: if.h,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 *
 * Dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _NETINET_IN_H
#  include <netinet/in.h>
#endif

#define isClassA(_addr)	(!(_addr & htonl(0x80000000)))
#define isClassB(_addr)	((_addr & htonl(0xc0000000)) == htonl(0x80000000))
#define isClassC(_addr)	((_addr & htonl(0xe0000000)) == htonl(0xc0000000))

struct ifinfo {
	char ifname[IFNAMSIZ];
	u_long	addr;				/* network byte order */
	u_long	mask;				/* network byte order */
	u_long	bcast;				/* network byte order */
	u_char	haddr[6];
	short	flags;
};

/* global variables in if.c
 */
extern struct ifinfo Ifbuf;


/* function prototypes
 */
void	ifReset(char *ifname);
/*  requires: 'ifname' points interface name which is going to be reset
 *  effects:  it resets the specified interface as follows:
 *             ifaddr: 0.0.0.0, netmask: 0.0.0.0, bcast: 255.255.255.255,
 *             flags: UP, BROADCAST, NOTRAILERS, RUN
 *  modifies: Nothing
 *  return:   Nothing
 */

void	ifConfig(struct ifinfo *ifbuf);
/*  requires: 'ifbuf' pointing the structure containing interface information
 *            to be set.
 *  effects:  it sets interface's IP addr, netmask, bcast addr, flags
 *            according to '*ifbuf'. it also sets route to the directly
 *            connected network.
 *  modifies: Nothing
 *  return:   Nothing
 */

void	ifDown(struct ifinfo *ifbuf);
/*  requires: 'ifbuf' pointing the structure containing interface information
 *            to be down.
 *  effects:  it makes the specified interface dwon.
 *  modifies: Nothing
 *  return:   Nothing
 */

u_long	getNaturalMask(u_long inaddr);
/*  requires: 'inaddr' containing IP address (network byte order).
 *  effects:  it returns natural netmask of 'inaddr'.
 *  modifies: Nothing
 *  return:   Nothing
 */

u_long	getNaturalBcast(u_long inaddr);
/*  requires: 'inaddr' containing IP address (network byte order).
 *  effects:  it returns natural broadcast address of 'inaddr'.
 *  modifies: Nothing
 *  return:   Nothing
 */

void	saveIfInfo(struct ifinfo *ifbuf);
/*  requires: 'ifbuf' pointing to the structure containing interface info.
 *  effects:  it saves '*ifbuf' onto the file DHCP_CACHE_FILE
 *  modifies: Nothing
 *  return:   Nothing
 */

void	getIfInfo(struct ifinfo *ifbuf);
/*  requires: 'ifbuf' pointing to the structure where interface info. is saved
 *  effects:  it saves interface information to '*ifbuf'
 *  modifies: Nothing
 *  return:   Nothing
 */

void	setDefRoute(const char *routers, struct ifinfo *ifinfo);
/*  requires: 'routers' pointing to the length field of the router option in
 *            a DHCP message. So the addresses are stored in the network byte
 *            order.
 *            'ifinfo' containing the interface name, at least.
 *  effects:  it sets the default route. 
 *  modifies: Nothing
 *  return:   Nothing
 */
