/* $Id: socket-if.c,v 1.5 2001-06-22 03:32:53 davidm Exp $
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
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dhcp.h"
#include "dhcp-options.h"
#include "error-handler.h"
#include "if.h"
#include "client.h"

void
setSockAddrIn(u_short port, u_long inaddr, struct sockaddr_in *saddr)
{
	bzero((char *)saddr, sizeof(*saddr));
	saddr->sin_family		= AF_INET;
	saddr->sin_addr.s_addr	= inaddr;
	saddr->sin_port			= port;
}

void
openSendSocket(struct sockaddr_in *addr, int *s)
{
	int optval = 1;

	if ( (*s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		logSysExit("socket (openSendSocket)");
	}
#if CONFIG_NETtel
	/* A NETtel can have a DHCP server && a client running at the same
	 * time -- REUSEADDR avoids a client bind error */
	/* added REUSEADDR 4 Jan, 2k. -m2 */
	if(setsockopt(*s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		logSysExit("setsockopt SO_REUSEADDR (openSendSocket)");
	}
#endif
	if(setsockopt(*s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
		logSysExit("setsockopt (openSendSocket)");
	}
	/* use DHCP client port for the source port because
	 * some servers do NOT use the DHCP client port
	 * BUT use the UDP source port number of the received
	 * datagram for the destination UDP port when it responds
	 * to clients.
	 */
	addr->sin_port = htons(DHCP_CLIENT_PORT);
#if 0
	addr->sin_port = htons(0);	/* appropriate unused port */
#endif
	if ( bind(*s, (struct sockaddr *)addr, sizeof(*addr))  < 0 ) {
		logSysExit("bind (openSendSocket)");
	}
}

void
openRecvSocket(struct sockaddr_in *addr, int *s)
{
	int optval = 1;

	if ( (*s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		logSysExit("socket (openRecvSocket)");
	}
	if ( setsockopt(*s, SOL_SOCKET, SO_BROADCAST, &optval,
					sizeof(optval)) < 0) {
		logSysExit("setsockopt (openRecvSocket)");
	}
	addr->sin_port = htons(DHCP_CLIENT_PORT);
	if ( bind(*s, (struct sockaddr *)addr, sizeof(*addr))  < 0 ) {
		logSysExit("bind (openRecvSocket)");
	}
}

void openRawSocket(int *s, u_short type)
{
	int optval = 1;

	if ( (*s = socket(AF_INET, SOCK_PACKET, htons(type))) < 0 ) {
		logSysExit("socket (openRawSocket)");
	}
	if ( setsockopt(*s, SOL_SOCKET, SO_BROADCAST,
					&optval, sizeof(optval)) < 0 ) {
		logSysExit("setsockopt (openRawSocket)");
	}
}

int
rcvAndCheckDhcpMsg(int s, dhcpMessage *msg, u_long waitMsgType,
				   u_char *optp[], long timeout)
{
	fd_set fdset;
	time_t prevTime;
	struct sockaddr_in addr;
	struct timeval tm;
	int len;

	bzero((char *)msg, sizeof(*msg));
	bzero((char *)&addr, sizeof(addr));
	tm.tv_sec = 0;
	time(&prevTime); 
	while ( timeout > 0 ) {
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		tm.tv_usec  = timeout;
		if ( select(s+1, &fdset,
					(fd_set *)NULL, (fd_set *)NULL, &tm) < 0 ) {
			logSysRet("select (rcvAndCheckDhcpMsg)");
			return 0;			/* receive unsuccessful */
		}
		len = sizeof(*msg);
		if ( FD_ISSET(s, &fdset) ) {
			if ( recvfrom(s, (char *)msg, len, 0,
						  (struct sockaddr *)&addr, &len) < 0 ) {
				logSysRet("recvfrom (rcvAndCheckDhcpMsg)");
				return 0;		/* receive unsuccessful */
			}
			if ( parseDhcpMsg(optp, msg) ) {
				if ( waitMsgType & (1 << (*(optp[OmsgType]+1)-1)) ) {
					return 1;
				}
			}
		}
		timeout -= (time(NULL) - prevTime)*1000000;
		time(&prevTime);
	}
	return 0;					/* receive timeout */
}

int
waitChkReXmitMsg(int sRecv, dhcpMessage *pMsgRecv,
				 int sSend, dhcpMessage *pMsgSend,
				 struct sockaddr_in *addr, u_long waitMsgType,
				 u_char *optp[], int nretry)
{
	long	tm;

	tm = getNextTimeout(INIT_TIMEOUT);
	while ( nretry-- ) {
		if ( rcvAndCheckDhcpMsg(sRecv, pMsgRecv, waitMsgType, optp, tm) ) {
				return 1;
		}
#ifdef LLIP_SUPPORT
		if (!linkLocalSet)
		{
			if ( sendto(sSend, (char *)pMsgSend, sizeof(*pMsgSend), 0,
				(struct sockaddr *)addr, sizeof(*addr)) < 0 ) {
				logSysExit("sendto (waitChkReXmitMsg)");
			}
		}
		else	
			sendrawpacket();
#else
		if ( sendto(sSend, (char *)pMsgSend, sizeof(*pMsgSend), 0,
					(struct sockaddr *)addr, sizeof(*addr)) < 0 ) {
			logSysExit("sendto (waitChkReXmitMsg)");
		}
#endif
		tm = getNextTimeout(NEXT_TIMEOUT);
	}
	return 0;
}

void
setWaitMsgType(int type, u_int *ptype)
{
	*ptype |= (1 << (type-1));
}
