/* $Id: arp.c,v 1.5 2007-06-27 06:10:27 gerg Exp $
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "dhcp.h"
#include "if.h"
#include "arp.h"
#include "socket-if.h"
#include "error-handler.h"


int
arpCheck(u_long inaddr, struct ifinfo *ifbuf, long timeout)
{
	int				s;			/* socket */
	int				rv;			/* return value */
	struct sockaddr addr;		/* for interface name */
	struct arpMsg	arp;
	fd_set			fdset;
	struct timeval	tm;
	time_t			prevTime;

	rv = 1;
	openRawSocket(&s, ETH_P_ARP);

	/* send arp request
	 */
	mkArpMsg(ARPOP_REQUEST, inaddr, NULL, ifbuf->addr, ifbuf->haddr, &arp);
	bzero(&addr, sizeof(addr));
	strcpy(addr.sa_data, ifbuf->ifname);
	if ( sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0 ) {
		logSysRet("sendto (arpCheck)");
		rv = 0;
	}
	/* wait arp reply, and check it
	 */
	tm.tv_usec = 0;
	time(&prevTime);
	while ( timeout > 0 ) {
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		tm.tv_sec  = timeout;
		if ( select(s+1, &fdset, (fd_set *)NULL, (fd_set *)NULL, &tm) < 0 ) {
			logSysRet("select (arpCheck)");
			rv = 0;
		}
		if ( FD_ISSET(s, &fdset) ) {
			if (recv(s, &arp, sizeof(arp), 0) < 0 ) {
				logSysRet("recv (arpCheck)");
				rv = 0;
			}
			if ( arp.operation == htons(ARPOP_REPLY) &&
				memcmp(arp.tHaddr, ifbuf->haddr, 6) == 0 &&
				*((u_int *)arp.sInaddr) == inaddr ) {
				rv = 0;
				break;
			}
		}
		timeout -= time(NULL) - prevTime;
		time(&prevTime);
	}
	close(s);
	return rv;
}

void
sendArpReply(u_char *thaddr, u_long tinaddr, struct ifinfo *ifbuf)
{
	int				s;			/* socket */
	struct sockaddr addr;		/* for interface name */
	struct arpMsg	arp;

	openRawSocket(&s, ETH_P_ARP);

	/* send arp reply
	 */
	mkArpMsg(ARPOP_REPLY, tinaddr, thaddr, ifbuf->addr, ifbuf->haddr, &arp);
	bzero(&addr, sizeof(addr));
	strcpy(addr.sa_data, ifbuf->ifname);
	if ( sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0 ) {
		logSysRet("sendto (arpCheck)");
	}
}

void
mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr,
		 u_long sInaddr, u_char *sHaddr, struct arpMsg *msg)
{
	bzero(msg, sizeof(*msg));
	bcopy(MAC_BCAST_ADDR, msg->ethhdr.h_dest, 6); /* MAC DA */
	bcopy(sHaddr, msg->ethhdr.h_source, 6);	/* MAC SA */
	msg->ethhdr.h_proto = htons(ETH_P_ARP);	/* protocol type (Ethernet) */
	msg->htype = htons(ARPHRD_ETHER);		/* hardware type */
	msg->ptype = htons(ETH_P_IP);			/* protocol type (ARP message) */
	msg->hlen = 6;							/* hardware address length */
	msg->plen = 4;							/* protocol address length */
	msg->operation = htons(opcode);			/* ARP op code */
	*((u_int *)msg->sInaddr) = sInaddr;		/* source IP address */
	bcopy(sHaddr, msg->sHaddr, 6);			/* source hardware address */
	*((u_int *)msg->tInaddr) = tInaddr;		/* target IP address */
	if ( opcode == ARPOP_REPLY ) {
		bcopy(tHaddr, msg->tHaddr, 6);		/* target hardware address */
	}
}
