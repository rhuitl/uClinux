/* $Id: options.c,v 1.3 2007-06-27 06:10:27 gerg Exp $
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

#include <sys/types.h>
#include <string.h>

#include "dhcp.h"
#include "dhcp-options.h"
#include "error-handler.h"


/* I don't like this way of doing DHCP option len sizes -m2 */
#if 0
/* length of each option. -1 means 'n'.
 */
static char OptLen[256] = {
	 0,							/* 0: pad */
	 4,
	 4,
	-1,
	-1,
	-1,							/* 5: Name Server */
	-1,
	-1,
	-1,
	-1,
	-1,							/* 10: Impress Server */
	-1,
	-1,
	 2,
	-1,
	-1,							/* 15: Domain Name */
	-1,
	-1,
	-1,
	 1,
	 1,						/* 20: Non-Local Source Routing Enable/Disable */
	-1,
	 2,
	 1,
	 4,
	-1,							/* 25: Path MTU Plateau Table */
	 2,
	 1,
	 4,
	 1,
	 1,							/* 30: Mask Supplier */
	 1,
	 4,
	-1,
	 1,
	 4,							/* 35: ARP Cache Timeout */
	 1,
	 1,
	 4,
	 1,
	-1,							/* 40: NIS Domain */
	-1,
	-1,
	-1,
	-1,
	-1,							/* 45: NetBIOS over TCP/IP... */
	 1,
	-1,
	-1,
	-1,
	 4,							/* 50: Requested IP address (DHCP) */
	 4,
	 1,
	 1,
	 4,
	-1,							/* 55: Parameter Request List (DHCP) */
	-1,
	 2,
	 4,
	 4,
	-1,							/* 60: Class Identifier (DHCP) */
	-1,
	 0,
};
#endif


/* opt must have 312 elements.
 */
void
getOptions(u_char *optp[], dhcpMessage *msg)
{
	u_char *p;
	u_char *end;
	int		len;
	int		i;

	p = msg->options + 4;		/* skip magic cookie */
	end = msg-> options + sizeof(msg->options);	/* last element + 1 */

	i = 0;
	bzero((u_char *)optp, sizeof(msg->options) * sizeof(u_char *));
	while ( p < end ) {
		if ( *p == endOption ) { /* end */
			return;
		}
		if ( *p == padOption ) { /* pad */
			++p;
			continue;
		}
		/* get the length of this tag code
		 */
#if 0
		len = (OptLen[*p] == -1) ? p[1] : OptLen[*p];
#else
		len = p[1];
#endif
		optp[i++] = p;			/* store the pointer to the tag */
		p += len + 2;			/* set the pointer to the next tag */
	}
	return;
}

/* optp must contain pointers to msg->option
 * return 1 if msg is good
 * return 0 if msg is not good
 * optp[Oxxx] has the pointer to the option field if msg is good
 * see dhcp.h for more details on Oxxx
 * CAUTION: This function uses DhcpMsgSend directly!!
 */
int
parseDhcpMsg(u_char *optp[], dhcpMessage *msg)
{
	char    buf[512];
	u_char *opt[N_SUPPORT_OPTIONS];
	u_char **p = optp;

	if ( msg->op != BOOTREPLY ) {
		return 0;				/* NG */
	}
	if ( msg->xid != DhcpMsgSend.xid ) {
		return 0;				/* NG */
	}
	if ( memcmp(msg->chaddr, DhcpMsgSend.chaddr, DhcpMsgSend.hlen) ) {
		return 0;				/* NG */
	}
	bzero((char *)opt, sizeof(opt));
	getOptions(p, msg);			/* get pointers to each option */
	for (; *p != NULL; ++p ) {
		switch ( **p ) {
		  case dhcpMessageType:
			opt[OmsgType] = *p + 1;
			break;
		  case dhcpServerIdentifier:
			opt[OserverInaddr] = *p + 1;
			break;
		  case dhcpIPaddrLeaseTime:
			opt[OleaseTime] = *p + 1;
			break;
		  case dhcpT1value:
			opt[OrenewalTime] = *p + 1;
			break;
		  case dhcpT2value:
			opt[OrebindTime] = *p + 1;
			break;
		  case subnetMask:
			opt[Onetmask] = *p + 1;
			break;
		  case broadcastAddr:
			opt[ObcastInaddr] = *p + 1;
			break;
		  case timeServer:
			opt[OtimeServer] = ( (*p)[1]%4 ) ? NULL : *p + 1;
			break;
		  case dns:
			opt[Odns] = ( (*p)[1]%4 ) ? NULL : *p + 1;
			break;
		  case lprServer:
			opt[OlprServer] = ( (*p)[1]%4 ) ? NULL : *p + 1;
			break;
		  case hostName:
			opt[OhostName] = *p + 1;
			break;
		  case domainName:
			opt[OdomainName] = *p + 1;
			break;
		  case nisDomainName:
			opt[OnisDomName] = *p + 1;
			break;
		  case ntpServers:
			opt[OntpServer] = ( (*p)[1]%4 ) ? NULL : *p + 1;
			break;
		  case dhcpMsg:
			strcpy(buf, "msg from the DHCP server: ");
			strncat(buf, *p + 2, (*p)[1]);
			logRet(buf);
			opt[OdhcpMessage] = *p + 1;
			break;
		  case dhcpClassIdentifier:
			opt[OdhcpClassId] = ( (*p)[1]%4 ) ? NULL : *p + 1;
			break;
		  case routersOnSubnet:
			opt[Orouter] = ( (*p)[1]%4 ) ? NULL : *p + 1;
			break;
		  default:
			break;
		}
	}
	bcopy(opt, optp, sizeof(opt));

	/* check option field
	 */
	if ( optp[OmsgType] == NULL ) {	/* illegal DHCP msg, or BOOTP msg */
		return 0;
	}
	/* DHCPOFFER & DHCPACK msgs must have server IP addres and lease time
	 */
	switch ( *optp[OmsgType] ) {
	  case DHCP_OFFER:
		if ( optp[OleaseTime] == NULL ) {
			logRet("No leasetime (msgType: %d) (parseDhcpMsg)",
				   *optp[OmsgType]);
			return 0;
		}
	  case DHCP_ACK:
		if ( optp[OserverInaddr] == NULL ) {
			logRet("No server IP address (msgType: %d) (parseDhcpMsg)",
				   *optp[OmsgType]);
			return 0;
		}
		break;
	  default:
		break;
	}
	return 1;
}
