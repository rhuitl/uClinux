/* $Id: client.c,v 1.11 2001-09-07 05:33:18 davidm Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 *
 * dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* #include <linux/autoconf.h>*/
#include "if.h"
#include "dhcp.h"
#include "dhcp-options.h"
#include "socket-if.h"
#include "arp.h"
#include "error-handler.h"
#include "hostinfo.h"
#include "client.h"

#ifdef CONFIG_NETtel
#include <linux/ledman.h>
#include "ip_nettel.h"
#endif
#ifdef EMBED
#define	random	rand
#endif

#ifdef LLIP_SUPPORT
#include <linux/version.h>
#include <syslog.h>
#include "llip.h"
extern	int	AutoIP;

#include <net/ethernet.h>
#include "udpipgen.h"

struct packed_ether_header {
  u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
  u_int16_t ether_type;                 /* packet type ID field */
} __attribute__((packed));

#define IPPACKET_SIZE           1500

typedef struct udpipMessage
{
  struct packed_ether_header    ethhdr;
  char   udpipmsg[IPPACKET_SIZE];
} __attribute__((packed)) udpipMessage;

void sendrawpacket();
int	linkLocalSet = 0;

#endif

extern int BeRFC1541;			/* if 1, Be RFC154 compliant */
extern char *Hostname;			/* if !NULL, put hostname into DHCP msg */
extern int Persistent;			/* if 1 then keep trying to acquire */
extern int ArpCheck;			/* if 1 then check if address used */

int (*Fsm[MAX_STATES])();		/* finite state machine */
int CurrState;					/* current state */
int PrevState;					/* previous state */

dhcpMessage DhcpMsgSend;		/* DHCP message to send */
dhcpMessage DhcpMsgRecv;		/* DHCP message received */

int Ssend;						/* socket fd for send */
int Srecv;						/* socket fd for receive */

time_t ReqSentTime;				/* time when DHCPREQUEST message is sent */
u_long SuggestLeaseTime = 0;	/* lease time suggested by the user */

/* DHCP information
*/
u_long ServerInaddr;			/* Server's IP address (network byte order) */
u_long LeaseTime;				/* lease time (network byte order) */
u_long RenewTime;				/* T1 time (network byte order) */
u_long RebindTime;				/* T2 time (network byte order) */

static u_char *OptPtr[MAXNOPT];	/* array of ptrs to DHCP option element */
static u_char *OptOffer[MAXNOPT];	/* same as above in DHCPOFFER msg */
static u_char ClassId[MAXIDCHARS];	/* class identifier */
static u_char ClientId[MAXIDCHARS];	/* client identifier */


void
classIDsetup(char *id)
{
	struct utsname		sname;

	if ( id != NULL ) {
		strncpy(ClassId, id, sizeof(ClassId));
		return;
	}
	/* setup default class identifier if id is NULL
	 */
	if ( uname(&sname) < 0 ) {
		logSysExit("uname (dhcpMsgInit)");
	}
	sprintf(ClassId, "%s %s %s", sname.sysname, sname.release, sname.machine);
}

void
clientIDsetup(char *id, char *ifname)
{
	struct  ifinfo ifinfo;
	u_char *s;
	int		len;

	s = ClientId;
	*s++ = 61;					/* type value of client identifier */

	if ( id != NULL ) {
		len = strlen(id);
		if ( len > sizeof(ClientId) - 4 ) {
			/* 4: code, len, type, EOS */
			logQuit("clientIDsetup: too long client ID string");
		}
		*s++ = len + 1;			/* 1 for the # field */
		*s++ = 0;				/* type: string */
		strcpy(s, id);
		return;
	}
	/* setup default client identifier if id is NULL
	 */
	strcpy(ifinfo.ifname, ifname);
	getIfInfo(&ifinfo);
	*s++ = 7;					/* length: 6 (MAC Addr) + 1 (# field) */
	*s++ = ARPHRD_ETHER;		/* type: Ethernet address */
	bcopy(ifinfo.haddr, s, sizeof(ifinfo.haddr));
}

void
dhcpMsgInit(u_char *ifname)
{
	struct sockaddr_in	addr;

#if 0
	/* open and bind socket for receiving
	 */
	setSockAddrIn(htons(0), htonl(INADDR_ANY), &addr);
	openRecvSocket(&addr, &Srecv);
#endif

	/* open and bind socket for sending
	 */
	setSockAddrIn(htons(DHCP_CLIENT_PORT), htonl(INADDR_ANY), &addr);
	openSendSocket(&addr, &Ssend);

#ifdef SO_BINDTODEVICE
{
	struct ifreq intf;

	logRet("Binding to interface '%s'\n", ifname);
	bzero(&intf, sizeof(intf));
	strncpy(intf.ifr_name, ifname, IFNAMSIZ);
	if (setsockopt(Ssend,SOL_SOCKET,SO_BINDTODEVICE,&intf,sizeof(intf)) < 0)
		logSysExit("setsockopt(SO_BINDTODEVICE)");
}
#endif

	Srecv = Ssend;
}

void
dhcpClient()
{
	int next_state;
#ifdef	LLIP_SUPPORT
	int	dhcpRequestFailCount = 0;
#endif

	Fsm[INIT_REBOOT] = initReboot;
	Fsm[INIT]		 = init;
	Fsm[REBOOTING]	 = rebooting;
	Fsm[SELECTING]	 = selecting;
	Fsm[REQUESTING]	 = requesting;
	Fsm[BOUND]		 = bound;
	Fsm[RENEWING]	 = renewing;
	Fsm[REBINDING]	 = rebinding;

retry:
	CurrState = PrevState = INIT_REBOOT;

	for(;;) {
#ifdef	LLIP_SUPPORT
	if ( AutoIP && !linkLocalSet && CurrState == INIT_REBOOT)
	{
		dhcpRequestFailCount++;
		if ( dhcpRequestFailCount > 1)
		{ u_int32_t autoIp_addr;
			if (setup_link_local_if(Ifbuf.ifname, &autoIp_addr)==0) {
				linkLocalSet = 1;
				dhcpRequestFailCount = 0; /* reset fail counter */
#ifdef CONFIG_NETtel
                                ipfwadm_rules(Ifbuf.ifname, autoIp_addr);
#endif

			}
			else
				syslog(LOG_INFO, "Link local IP assignment failed");
		}
	}
#endif

		next_state = (*Fsm[CurrState])();
		if ( next_state == EXCEPTION ) {
			if (Persistent)
				goto retry;
			errQuit("Exception occured in the fsm (dhcpClient)");
		}
		PrevState = CurrState;
		CurrState  = next_state;
	}
}

int
initReboot()
{
#ifdef EMBED
	return INIT;
#else
	int					fd;
	int					nextState = REBOOTING;
	char				filename[IFNAMSIZ + 128];
	struct sockaddr_in	addr;

	bzero((char *)&addr, sizeof(addr));
	strcpy(filename, DHCP_CACHE_FILE);
	strcat(filename, Ifbuf.ifname);
	if ( (fd = open(filename, O_RDONLY)) < 0 ) {
		return INIT;
	}
	/* try to open cache file
	 */
	if ( read(fd, (char *)&addr.sin_addr.s_addr,
			  sizeof(addr.sin_addr.s_addr)) < 0 ) {
		nextState = INIT;
	}
	close(fd);
	unlink(filename);
	if ( nextState != REBOOTING ) {
		return nextState;
	}
	/* found cache file
	 */
	mkDhcpDiscoverMsg(Ifbuf.haddr, &DhcpMsgSend); /* set up MAC adddr, etc. */
	/* TODO: cache file should have the lease time previously used
	 */
	mkDhcpRequestMsg(REBOOTING, 0, 0, rand(),
					 addr.sin_addr.s_addr, &DhcpMsgSend);
#ifndef LLIP_SUPPORT
	setSockAddrIn(htons(DHCP_SERVER_PORT), htonl(INADDR_BROADCAST), &addr);
#else
	sendrawpacket();
#endif

	time(&ReqSentTime);
#ifdef NEED_BCAST_RESPONSE
	DhcpMsgSend.flags = htons(F_BROADCAST);
#endif
#ifndef LLIP_SUPPORT
	if ( sendto(Ssend, (char *)&DhcpMsgSend, sizeof(DhcpMsgSend), 0,
				(struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
		logSysExit("sendto (initReboot)");
	}
#endif
	return REBOOTING;
#endif
}

int
init()
{
	char ifname[IFNAMSIZ];
	int waitTime = 0;
	struct sockaddr_in	addr;

	freeOptInfo(OptOffer);		/* clear up 'OptOffer' */
	if ( PrevState == RENEWING || PrevState == REBINDING ) {
		strcpy(ifname, Ifbuf.ifname);
#ifdef LLIP_SUPPORT 
		if (!linkLocalSet)
			ifReset(ifname);
#else
		ifReset(ifname);
#endif

		dhcpMsgInit(Ifbuf.ifname);
	}
	mkDhcpDiscoverMsg(Ifbuf.haddr, &DhcpMsgSend);
#ifndef LLIP_SUPPORT
	setSockAddrIn(htons(DHCP_SERVER_PORT), htonl(INADDR_BROADCAST), &addr);
#endif

#if 0
	do {
		waitTime = random() % 10;
	} while ( waitTime == 0 );
	sleep(waitTime);
#endif
	time(&ReqSentTime);			/* record local time
								   not @ REQUEST but @ DISCOVER (RFC1541) */
#ifndef LLIP_SUPPORT
	if ( sendto(Ssend, (char *)&DhcpMsgSend, sizeof(DhcpMsgSend), 0,
				(struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
		logSysExit("sendto (init)");
	}
#else
	sendrawpacket();
#endif
	return SELECTING;
}

int
rebooting()
{
	int					 nextState;
	struct sockaddr_in	 addr;
	u_int				 waitMsgType;

	setSockAddrIn(htons(DHCP_SERVER_PORT), htonl(INADDR_BROADCAST), &addr);
	waitMsgType			 = 0;
	setWaitMsgType(DHCP_ACK, &waitMsgType);
	setWaitMsgType(DHCP_NAK, &waitMsgType);

	/* DhcpMsgSend should contain DHCPREQUEST message (created in initReboot).
	 */
	if ( !waitChkReXmitMsg(Srecv, &DhcpMsgRecv, Ssend, &DhcpMsgSend,
					   &addr, waitMsgType, OptPtr, N_REXMIT_REQ_REBOOT) ) {
		logRet("REBOOTING: timeout. Fall back to INIT");
		return INIT;
	}
	nextState = setDhcpInfo(OptPtr, &DhcpMsgRecv);
	if ( nextState == BOUND ) {
		/* check if yiaddr is already used
		 */
		if ( !arpCheck(DhcpMsgRecv.yiaddr, &Ifbuf, ARP_REPLY_TIMEOUT) ) {
			sendDhcpDecline(DHCP_DECLINE,
							*((u_int *)(OptPtr[OserverInaddr]+1)),
							DhcpMsgRecv.yiaddr);
			sleep(10);
			logRet("REBOOTING: %s is already used. Fall back to INIT",
				   inet_ntoa(*((struct in_addr *)&DhcpMsgRecv.yiaddr)));
			return INIT;
		}
		/* now the client is initialized
		 */

		/* initHost uses the values of Ifbuf.bcast and Ifbuf.mask as is
		 * under the following condition:
		 *   1. the DHCP ACK msg does not includes bcast or subnetmask option
		 *   2. Ifbuf.bcast or Ifbuf.mask is not 0.
		 * So we have to set these values to 0 not to confuse initHost.
		 */
		Ifbuf.bcast = Ifbuf.mask = 0;
		initHost(&Ifbuf, DhcpMsgRecv.yiaddr);
		execCommandFile();
		if ( LeaseTime == INFINITE_LEASE_TIME ) {
			logRet("got the INFINITE lease time. exit(0).");
			die(0);
#ifdef CONFIG_NETtel
		} else {
			if (strchr(Ifname, '0'))
				ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN1_DHCP);
			else if (strchr(Ifname, '1'))
				ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN2_DHCP);
#endif
		}
	} else if ( nextState == INIT ) {
		logRet("REBOOTING: got DHCPNAK. Fall back to INIT");
	}
	return nextState;
}

int
selecting()
{
	time_t				 prevTime;
	struct sockaddr_in	 addr;
	u_int				 waitMsgType;

	time(&prevTime);

	setSockAddrIn(htons(DHCP_SERVER_PORT), htonl(INADDR_BROADCAST), &addr);

	/* DhcpMsgSend shoud contain DHCPDISCOVER message (created in 'init')
	 */
	waitMsgType			 = 0;
	setWaitMsgType(DHCP_OFFER, &waitMsgType);
	if ( waitChkReXmitMsg(Srecv, &DhcpMsgRecv, Ssend, &DhcpMsgSend,
						  &addr, waitMsgType, OptPtr, N_REXMIT_DISCOVER) ) {
		/* send DHCPREQUEST msessage
		 */
		ServerInaddr = *((u_int *)(OptPtr[OserverInaddr]+1));
		LeaseTime	 = *((u_int *)(OptPtr[OleaseTime]+1));
		mkDhcpRequestMsg(SELECTING, ServerInaddr, LeaseTime,
							 DhcpMsgRecv.xid, DhcpMsgRecv.yiaddr,
							 &DhcpMsgSend);
#ifdef NEED_BCAST_RESPONSE
		DhcpMsgSend.flags = htons(F_BROADCAST);
#endif

#ifdef LLIP_SUPPORT
		if (!linkLocalSet) {
			if ( sendto(Ssend, (char *)&DhcpMsgSend, sizeof(DhcpMsgSend), 0,
					(struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
				logSysExit("sendto (selecting)");
			}
		}
		else
		{
			sendrawpacket();
		}
#else
		if ( sendto(Ssend, (char *)&DhcpMsgSend, sizeof(DhcpMsgSend), 0,
					(struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
			logSysExit("sendto (selecting)");
		}
#endif
		/* record option values in the DHCPOFFER message because NT server
		   does not include those values in the DHCPACK message
		 */
		setupIfInfo(&Ifbuf, DhcpMsgRecv.yiaddr, OptPtr);
		setupOptInfo(OptOffer, (const u_char **)OptPtr);
		return REQUESTING;
	}
	if (! Persistent)
		ifDown(&Ifbuf);
	logRet("no DHCPOFFER messages");
	return EXCEPTION;			/* should not happen */
}

int
requesting()
{
	struct sockaddr_in	 addr;
	int					 nextState;
	u_int				 waitMsgType;

	/* wait DHCPACK/DHCPNAK, rexmit RHCPREQUEST if necessary
	 */
	setSockAddrIn(htons(DHCP_SERVER_PORT), htonl(INADDR_BROADCAST), &addr);
	waitMsgType = 0;
	setWaitMsgType(DHCP_ACK, &waitMsgType);
	setWaitMsgType(DHCP_NAK, &waitMsgType);
	if ( waitChkReXmitMsg(Srecv, &DhcpMsgRecv, Ssend, &DhcpMsgSend,
						  &addr, waitMsgType, OptPtr, N_REXMIT_REQUEST) ) {
		if ( (nextState = setDhcpInfo(OptPtr, &DhcpMsgRecv)) != EXCEPTION ) {
			if ( nextState == BOUND ) {
				/* check if yiaddr is already used
				 */
				Ifbuf.addr = htonl(0);	/* sender's IP address must be 0 */
				if ( ArpCheck && !arpCheck(DhcpMsgRecv.yiaddr, &Ifbuf,
							   ARP_REPLY_TIMEOUT) ) {
					sendDhcpDecline(DHCP_DECLINE,
									*((u_int *)(OptPtr[OserverInaddr]+1)),
									DhcpMsgRecv.yiaddr);
					logRet("REQUESTING: %s is already used. Fall back to INIT",
						   inet_ntoa(*((struct in_addr *)
									   &DhcpMsgRecv.yiaddr)));
					sleep(10);
					return INIT;
				}
				/* now the client is initialized
				 */
				setupOptInfo(OptOffer, (const u_char **)OptPtr);
				initHost(&Ifbuf, DhcpMsgRecv.yiaddr);
				sendArpReply(MAC_BCAST_ADDR, Ifbuf.bcast, &Ifbuf);
				execCommandFile();
#ifdef CONFIG_NETtel
				ipfwadm_rules(Ifbuf.ifname, DhcpMsgRecv.yiaddr);
#endif
				if ( LeaseTime == INFINITE_LEASE_TIME ) {
					logRet("got the INFINITE lease time. exit(0).");
					die(0);
#ifdef CONFIG_NETtel
				} else {
					if (strchr(Ifname, '0'))
						ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN1_DHCP);
					else if (strchr(Ifname, '1'))
						ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN2_DHCP);
#endif
				}
			}
			return nextState;
		}
	}
	logRet("no response to DHCPREEQUEST message. move to INIT state");
	return INIT;
}

int
bound()
{
	logRet("got in BOUND state");
	sleep(ntohl(RenewTime));
	return RENEWING;
}

int
renewing()
{
	struct sockaddr_in	 addr;
	int					 nextState;
	time_t				 sendTime;
	time_t				 prevTime;
	long				 timeout;
	long				 tm;
	u_int				 waitMsgType;

	logRet("got in RENEWING state");

	/* setup for sending unicast DHCPREQUEST message
	 */
	setSockAddrIn(htons(DHCP_SERVER_PORT), ServerInaddr, &addr);
	mkDhcpRequestMsg(RENEWING, ServerInaddr, LeaseTime,
					 rand(), Ifbuf.addr, &DhcpMsgSend);
	/* send DHCPREQUESTvia unicast, and
	 * wait server's response (DHCPACK/DHCPNAK)
	 */
	timeout = ReqSentTime + ntohl(RebindTime) - time(NULL);
	/* timeout     = ntohl(RebindTime) - ntohl(RenewTime); */
	nextState   = REBINDING;
	waitMsgType = 0;
	setWaitMsgType(DHCP_ACK, &waitMsgType);	/* wait DHCPACK, DHCPNAK */
	setWaitMsgType(DHCP_NAK, &waitMsgType);
	tm = getNextTimeout(INIT_TIMEOUT);
	time(&prevTime);
	while ( timeout > 0 ) {
		/* send DHCPREQUEST via unicast
		 */
		time(&sendTime);
		if ( sendto(Ssend, (char *)&DhcpMsgSend, sizeof(DhcpMsgSend), 0,
					(struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
			logSysRet("sendto (renewing)");
			sleep(tm/1000000);
		} else {
			/* wait server's response
			 */
			if ( rcvAndCheckDhcpMsg(Srecv, &DhcpMsgRecv,
									waitMsgType, OptPtr, tm) ) {
				nextState = setDhcpInfo(OptPtr, &DhcpMsgRecv);
				if ( nextState == EXCEPTION ) {
					return nextState;
				}
				break;
			}
		}
		tm = getNextTimeout(NEXT_TIMEOUT);	/* renew response timeout value */
		timeout -= time(NULL) - prevTime;
		time(&prevTime);
	}
	if ( nextState == BOUND ) {
		ReqSentTime = sendTime;			/* renew time when DHCPREQ is sent */
	} else if ( nextState == INIT ) {	/* got DHCPNAK */
		logRet("RENEWING: got DHCPNAK. Fall back to INIT");
		close(Ssend);
		close(Srecv);
		ifDown(&Ifbuf);
	}
	return nextState;
}

int
rebinding()
{
	struct sockaddr_in	 addr;
	int					 nextState;
	time_t				 sendTime;
	time_t				 prevTime;
	long				 timeout;
	long				 tm;
	u_int				 waitMsgType;

	logRet("got in REBINDING state");

	nextState = INIT;			/* init nextState */

	/* setup for sending broadcast DHCPREQUEST message
	 */
	setSockAddrIn(htons(DHCP_SERVER_PORT), Ifbuf.bcast, &addr);
	mkDhcpRequestMsg(REBINDING, ServerInaddr, LeaseTime,
					 rand(), Ifbuf.addr, &DhcpMsgSend);

	/* send DHCPREQUEST via broadcast, and
	 * wait server's response (DHCPACK/DHCPNAK)
	 */
	timeout = ReqSentTime + ntohl(LeaseTime) - time(NULL);
	/* timeout     = ntohl(LeaseTime) - ntohl(RebindTime); */
	waitMsgType = 0;
	setWaitMsgType(DHCP_ACK, &waitMsgType);	/* wait DHCPACK, DHCPNAK */
	setWaitMsgType(DHCP_NAK, &waitMsgType);
	tm = getNextTimeout(INIT_TIMEOUT);
	time(&prevTime);
	while ( timeout > 0 ) {
		time(&sendTime);
		if ( sendto(Ssend, (char *)&DhcpMsgSend, sizeof(DhcpMsgSend), 0,
					(struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
			logSysRet("sendto (rebinding)");
			sleep(tm/1000000);
		} else {
			if ( rcvAndCheckDhcpMsg(Srecv, &DhcpMsgRecv,
									waitMsgType, OptPtr, tm) ) {
				nextState = setDhcpInfo(OptPtr, &DhcpMsgRecv);
				if ( nextState == EXCEPTION ) {
					return nextState;
				}
				break;
			}
		}
		tm = getNextTimeout(NEXT_TIMEOUT);
		timeout -= time(NULL) - prevTime;
		time(&prevTime);
	}
	if ( nextState == BOUND ) {
		ReqSentTime = sendTime;	/* renew time when DHCPREQ is sent */
		return nextState;
	}
	/* Lease expired. halt network
	 */
	logRet("REBINDING: Lease time expired. Fall back to INIT");
	close(Ssend);
	close(Srecv);
	ifDown(&Ifbuf);
	return INIT;
}

void
mkDhcpDiscoverMsg(u_char *haddr, dhcpMessage *msg)
{
	u_char *p =	msg->options + 4; /* just after the magic cookie */

	bzero((char *)msg, sizeof(*msg));
	msg->htype = HTYPE_ETHER;	/* supports Etherenet only */
	msg->hlen  = 6;
	bcopy(haddr, msg->chaddr, 6);
	msg->op	   = BOOTREQUEST;
#ifdef NEED_BCAST_RESPONSE
	msg->flags = htons(F_BROADCAST);
#endif
	msg->xid   = htonl(random());

	/* make DHCP message option field
	 */
	*((u_long *)msg->options) = htonl(MAGIC_COOKIE);
	*p++ = dhcpMessageType;		/* DHCP message type */
	*p++ = 1;
	*p++ = DHCP_DISCOVER;
	*p++ = dhcpMaxMsgSize;		/* Maximum DHCP message size */
	*p++ = 2;
	*((u_short *)p) = htons(sizeof(*msg));
	p += sizeof(u_short);
	if ( SuggestLeaseTime ) {
		*p++ = dhcpIPaddrLeaseTime;	/* IP address lease time */
		*p++ = 4;
		*((u_int *)p) = htonl(SuggestLeaseTime);
		p += sizeof(long);
	}
	*p++ = dhcpParamRequest;	/* Parameter Request List */
	*p++ = 8;					/* number of requests */
	*p++ = subnetMask;
	*p++ = routersOnSubnet;
	*p++ = dns;
	*p++ = hostName;
	*p++ = domainName;
	*p++ = broadcastAddr;
	*p++ = ntpServers;
	*p++ = nisDomainName;

	if ( Hostname != NULL ) {
		int len;

		len = strlen(Hostname);
		*p++ = hostName;
		*p++ = len;
		strncpy(p, Hostname, len);
		p += len;
	}
	*p++ = dhcpClassIdentifier;	/* class identifier */
	*p++ = strlen(ClassId);
	strcpy(p, ClassId);
	p += strlen(ClassId);
	bcopy(ClientId, p, ClientId[1]+2); /* client identifier */
	p += ClientId[1] + 2;
	*p = endOption;				/* end */
}

void
mkDhcpRequestMsg(int flag, u_long serverInaddr, u_long leaseTime,
				 u_long xid, u_long ciaddr, dhcpMessage *msg)
{
	u_char *p =	msg->options + 4; /* just after the magic cookie */

	msg->xid	= xid;
	msg->ciaddr = ciaddr;
	msg->flags = htons(0);		/* do not set the broadcast flag here */
	bzero((char *)p, sizeof(msg->options) - 4);	/* clear DHCP option field */

	/* 1. Requested IP address must not be in the DHCPREQUEST message
	 *    under the RFC1541 mode.
	 * 2. Requested IP address must be in the DHCPREQUEST message
	 *    sent in the SELECTING or INIT-REBOOT state under the Internet
	 *    Draft mode
	 */
	if ( !BeRFC1541 ) {
		if ( flag == REBOOTING || flag == SELECTING ) {
			/* ciaddr must be 0 in REBOOTING & SELECTING */
			msg->ciaddr = htonl(0);
			*p++ = dhcpRequestedIPaddr;
			*p++ = 4;
			*((u_int *)p) = ciaddr;
			p += sizeof(u_int);
		}
	}
	*p++ = dhcpMessageType;				/* DHCP message type */
	*p++ = 1;
	*p++ = DHCP_REQUEST;
	*p++ = dhcpMaxMsgSize;				/* Maximum DHCP message size */
	*p++ = 2;
	*((u_short *)p) = htons(sizeof(*msg));
	p += sizeof(u_short);
	if ( flag == REBOOTING && SuggestLeaseTime ) {
		*p++ = dhcpIPaddrLeaseTime;	/* IP address lease time */
		*p++ = 4;
		*((u_int *)p) = htonl(SuggestLeaseTime);
		p += sizeof(long);
	}
	if ( flag == SELECTING || flag == REQUESTING ) {
		*p++ = dhcpServerIdentifier;	/* server identifier */
		*p++ = 4;
		*((u_int *)p) = serverInaddr;
		p += sizeof(u_int);
	}
	if ( leaseTime != 0 ) {
		*p++ = dhcpIPaddrLeaseTime;		/* IP address lease time */
		*p++ = 4;
		*((u_int *)p) = leaseTime;
		p += sizeof(u_int);
	}
	*p++ = dhcpParamRequest;	/* Parameter Request List */
	*p++ = 8;					/* number of requests */
	*p++ = subnetMask;
	*p++ = routersOnSubnet;
	*p++ = dns;
	*p++ = hostName;
	*p++ = domainName;
	*p++ = broadcastAddr;
	*p++ = ntpServers;
	*p++ = nisDomainName;

	if ( Hostname != NULL ) {
		int len;

		len = strlen(Hostname);
		*p++ = hostName;
		*p++ = len;
		strncpy(p, Hostname, len);
		p += len;
	}
	*p++ = dhcpClassIdentifier;			/* class identifier */
	*p++ = strlen(ClassId);
	strcpy(p, ClassId);
	p += strlen(ClassId);
	bcopy(ClientId, p, ClientId[1]+2);	/* client identifier */
	p += ClientId[1] + 2;
	*p = endOption;						/* end */
}

void
mkDhcpDeclineMsg(int flag, u_long serverInaddr, u_long ciaddr,
				 dhcpMessage *msg)
{
	u_char *p =	msg->options + 4; /* just after the magic cookie */

	msg->xid	= rand();
	if ( flag == DHCP_RELEASE ) {	/* make a DHCPRELEASE msg */
		msg->ciaddr = ciaddr;
	} else {						/* make a DHCPDECLINE msg */
		if ( BeRFC1541 ) {			/* use ciaddr in RFC1541 compliant mode */
			msg->ciaddr = ciaddr;
		} else {
			msg->ciaddr = 0;
		}
	}

	bzero((char *)p, sizeof(msg->options) - 4);
	*p++ = dhcpMessageType;		/* DHCP message type */
	*p++ = 1;
	*p++ = (u_char)flag;
	*p++ = dhcpServerIdentifier; /* server identifier */
	*p++ = 4;
	*((u_int *)p) = serverInaddr;
	p += sizeof(long);
	if ( flag == DHCP_DECLINE && !BeRFC1541 ) {
		/* use the requested IP address option
		 * in the Internet Draft compliant mode
		 */
		*p++ = dhcpRequestedIPaddr;
		*p++ = 4;
		*((u_int *)p) = ciaddr;
		p += sizeof(u_int);
	}
	if ( Hostname != NULL ) {
		int len;

		len = strlen(Hostname);
		*p++ = hostName;
		*p++ = len;
		strncpy(p, Hostname, len);
		p += len;
	}
	bcopy(ClientId, p, ClientId[1]+2); /* client identifier */
	p += ClientId[1] + 2;
	*p = endOption;				/* end */
}

void
sendDhcpDecline(int flag, u_long serverInaddr, u_long ciaddr)
{
	struct sockaddr_in	 addr;

	bzero((char *)&addr, sizeof(addr));
	addr.sin_family 	 = AF_INET;
	addr.sin_port		 = htons(DHCP_SERVER_PORT);
	switch ( flag ) {
	  case DHCP_DECLINE:
		addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		break;
	  case DHCP_RELEASE:
		addr.sin_addr.s_addr = serverInaddr;
		break;
	  default:
		logQuit("illegal flag value (sendDhcpDecline)");
		break;
	}
	mkDhcpDeclineMsg(flag, serverInaddr, ciaddr, &DhcpMsgSend);
	if ( sendto(Ssend, (char *)&DhcpMsgSend, sizeof(DhcpMsgSend), 0,
				(struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
		logSysExit("sendto (sendDhcpDecline)");
	}
}

int
setDhcpInfo(u_char *optp[], dhcpMessage *msg)
{
	switch ( *(optp[OmsgType]+1) ) {
	  case DHCP_NAK:
		return INIT;
	  case DHCP_ACK:
		ServerInaddr = *((u_long *)(optp[OserverInaddr]+1));
		LeaseTime	 = *((u_long *)(optp[OleaseTime]+1));
#ifdef EMBED
		if (LeaseTime == 0)
			LeaseTime = INFINITE_LEASE_TIME;
#endif
		if ( optp[OrenewalTime] == NULL ) {
			RenewTime = htonl(ntohl(LeaseTime) / 2);		/* default T1 time */
		} else {
			RenewTime = *((u_long *)(optp[OrenewalTime]+1));
		}
		if ( optp[OrebindTime] == NULL ) {
			RebindTime = htonl(ntohl(LeaseTime) / 8 * 7);	/* default T2 time */
		} else {
			RebindTime = *((u_long *)(optp[OrebindTime]+1));
		}
		return BOUND;
	  default:
		return EXCEPTION;		/* should not happen */
	}
}

/* NOTE: this function is called from 'selecting()', and sets up the network
 *       interface information. It sets subnetmask and broadcast to 0 unless
 *       it receives these values. These values are set correctly in
 *       'initHost()'. This is for the following case: these values were in
 *       the DHCPOFFER message, and were not in the DHCPACK message. In this
 *       case, dhcpcd must not override these values with the 'natural'
 *       subenetmask and broadcast.
 */
void
setupIfInfo(struct ifinfo *ifbuf, u_long yiaddr, u_char *optp[])
{
	ifbuf->addr = yiaddr;
	if ( optp[Onetmask] != NULL ) {
		ifbuf->mask = *((u_int *)(optp[Onetmask]+1));
	} else {
		ifbuf->mask = 0;
	}
	if ( optp[ObcastInaddr] != NULL ) {
		ifbuf->bcast = *((u_int *)(optp[ObcastInaddr]+1));
	} else {
		ifbuf->bcast = 0;
	}
}

void
initHost(struct ifinfo *ifbuf, u_long yiaddr)
{
	/* configure interface
	 */
	ifbuf->addr  = yiaddr;
	logRet("responding Server:          %s",
		   inet_ntoa(*((struct in_addr *)&ServerInaddr)));
	logRet("assigned IP address:        %s",
		   inet_ntoa(*((struct in_addr *)&ifbuf->addr)));
	if ( OptPtr[Onetmask] == NULL ) {
		if ( ifbuf->mask == 0 ) {
			/* if ifbuf->mask != 0, subnetmask info. was included in the
			 *  DHCPOFFER message and not included in the DHCPACK message.
			 *  In this case, subnetmask value must not been overwritten.
			 */
			ifbuf->mask = getNaturalMask(ifbuf->addr);
		}
	} else {
		ifbuf->mask  = *((u_int *)(OptPtr[Onetmask]+1));
		logRet("assigned subnetmask:        %s",
			   inet_ntoa(*((struct in_addr *)&ifbuf->mask)));
	}
	if ( OptPtr[ObcastInaddr] == NULL ) {
		/* if the server responds only subnetmask, I should presume
		 * the broadcast address from the subnetmask instead of
		 * using the 'natural' broadcast address.
		 */
		if ( ifbuf->bcast == 0 ) {
			/* if ifbuf->bcast != 0, broadcast info. was included in the
			 *  DHCPOFFER message and not included in the DHCPACK message.
			 *  In this case, broadcast addr. must not been overwritten.
			 */
			ifbuf->bcast = (ifbuf->addr & ifbuf->mask) | ~ifbuf->mask;
		}
	} else {
		ifbuf->bcast = *((u_int *)(OptPtr[ObcastInaddr]+1));
		logRet("assigned broadcast address: %s",
			   inet_ntoa(*((struct in_addr *)&ifbuf->bcast)));
	}
	ifbuf->flags =
		IFF_UP | IFF_BROADCAST | IFF_NOTRAILERS | IFF_RUNNING | IFF_MULTICAST;
	ifConfig(ifbuf);

#ifndef EMBED
	saveIfInfo(ifbuf);			/* save interface information onto file */
#endif
	saveHostInfo((const u_char **)OptPtr);
}

long
getNextTimeout(int flag)
{
	static long  prevTimeout;
	long		 rv;			/* return value */

#ifdef EMBED
	if ( flag == INIT_TIMEOUT ) {
		prevTimeout = 2;		/* 2 seconds */
	} else if ( prevTimeout > 8 ) {
		prevTimeout = 4;
	}
#else
	if ( flag == INIT_TIMEOUT ) {
		prevTimeout = 4;		/* 4 seconds */
	} else if ( prevTimeout > 64 ) {
		prevTimeout = 4;
	}
#endif
	rv = (prevTimeout - 1) * 1000000 + rand()/2000000;
	prevTimeout *= 2;
	return rv;
}

#ifdef LLIP_SUPPORT

// sends a raw packet through the interface eg. eth0 with from IP address as 0.0.0.0
void sendrawpacket()
{
		struct sockaddr addr;
		int Ssend2; 
		udpipMessage UdpIpMsgSend; /* raw message */
		int optval = 1;

  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0)
		Ssend2 = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
  #else
		Ssend2 = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ALL));
  #endif
		if (Ssend2 == -1)
			logSysExit("socket (init)");

		if ( setsockopt(Ssend2, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) == -1) 
			logSysExit("setsockopt (init)");

		memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
		memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
		memcpy(UdpIpMsgSend.ethhdr.ether_shost,Ifbuf.haddr,ETH_ALEN);
		UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

		/* put request message into packet */
		memcpy(&UdpIpMsgSend.udpipmsg[sizeof(udpiphdr)],&DhcpMsgSend,sizeof(dhcpMessage));
 		/* build UDP/IP header */
		udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
			htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));


		memset(&addr,0,sizeof(struct sockaddr));
	        memcpy(addr.sa_data,&(Ifbuf.ifname),14);

		if ( sendto(Ssend2, &UdpIpMsgSend, sizeof(struct packed_ether_header)+
				sizeof(udpiphdr)+sizeof(dhcpMessage),0,
				&addr,sizeof(struct sockaddr)) == -1 )
		{
			logSysExit("sendto (init) : ");
		}

		close(Ssend2);
		return;

}
#endif
