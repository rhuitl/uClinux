/*
 * arpping.c
 *
 * Mostly stolen from: dhcpcd - DHCP client daemon
 * by Yoichi Hariguchi <yoichi@fore.com>
 */


#include "arpping.h"
#include "syslog.h"

#define DEBUG		0


/* local prototypes */
int arpCheck(u_long inaddr, struct ifinfo *ifbuf, long timeout);
void mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr, u_long sInaddr, u_char *sHaddr, struct arpMsg *msg);
int openRawSocket (int *s, u_short type);

extern char *interface_name;
extern unsigned char interface_hwaddr[];

/* args:	yiaddr - what IP to ping (eg. on the NETtel cb189701)
 * retn: 	1 addr free
 *		0 addr used
 *		-1 error 
 */  

int arpping(u_int32_t yiaddr)
{
	int rv;
	struct ifinfo ifbuf;
	int n;
	static int nr = 0;
	unsigned char *ep;
	
	strcpy(ifbuf.ifname, interface_name);
	ifbuf.addr = 0xcb1897aa; /* this addr appears to be irrelevant */
	ifbuf.mask = 0x0;
	ifbuf.bcast = 0x0;

	ep = &interface_hwaddr[0];
	
	for(n = 0; n < 6; n++)
		ifbuf.haddr[n] = ep[n];
	ifbuf.flags = 0;
	
	rv = arpCheck(yiaddr, &ifbuf, 3);
	return rv;
}


int arpCheck(u_long inaddr, struct ifinfo *ifbuf, long timeout)  {
	int				s;			/* socket */
	int				rv;			/* return value */
	struct sockaddr addr;		/* for interface name */
	struct arpMsg	arp;
	fd_set			fdset;
	struct timeval	tm;
	time_t			prevTime;

	rv = 1;
	openRawSocket(&s, ETH_P_ARP);

	/* send arp request */
	mkArpMsg(ARPOP_REQUEST, inaddr, NULL, ifbuf->addr, ifbuf->haddr, &arp);
	bzero(&addr, sizeof(addr));
	strcpy(addr.sa_data, ifbuf->ifname);
	if ( sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0 ) {
#if 0
		printf("sendto (arpCheck)");
#endif
		rv = 0;
	}
	
	/* wait arp reply, and check it */
	tm.tv_usec = 0;
	time(&prevTime);
	while ( timeout > 0 ) {
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		tm.tv_sec  = timeout;
		if ( select(s+1, &fdset, (fd_set *)NULL, (fd_set *)NULL, &tm) < 0 ) {
#if 0
			printf("select (arpCheck)");
#endif
			rv = 0;
		}
		if ( FD_ISSET(s, &fdset) ) {
			if (recv(s, &arp, sizeof(arp), 0) < 0 ) {
#if 0
				printf("recv (arpCheck)");
#endif
				rv = 0;
			}
			if (arp.operation == htons(ARPOP_REPLY) &&
					bcmp(arp.tHaddr, ifbuf->haddr, 6) == 0 &&
					bcmp(arp.sInaddr, &inaddr, sizeof(arp.sInaddr)) == 0) {
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

void mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr,
		 u_long sInaddr, u_char *sHaddr, struct arpMsg *msg) {
	bzero(msg, sizeof(*msg));
	bcopy(MAC_BCAST_ADDR, msg->ethhdr.ether_dhost, 6); /* MAC DA */
	bcopy(sHaddr, msg->ethhdr.ether_shost, 6);	/* MAC SA */
	msg->ethhdr.ether_type = htons(ETH_P_ARP);	/* protocol type (Ethernet) */
	msg->htype = htons(ARPHRD_ETHER);		/* hardware type */
	msg->ptype = htons(ETH_P_IP);			/* protocol type (ARP message) */
	msg->hlen = 6;							/* hardware address length */
	msg->plen = 4;							/* protocol address length */
	msg->operation = htons(opcode);			/* ARP op code */
	bcopy(&sInaddr, msg->sInaddr,
			sizeof(msg->sInaddr));			/* source IP address */
	bcopy(sHaddr, msg->sHaddr, 6);			/* source hardware address */
	bcopy(&tInaddr, msg->tInaddr,
			sizeof(msg->tInaddr));			/* target IP address */
	if ( opcode == ARPOP_REPLY ) {
		bcopy(tHaddr, msg->tHaddr, 6);		/* target hardware address */
	}
}


int openRawSocket (int *s, u_short type) {
	int optval = 1;

	if((*s = socket (AF_INET, SOCK_PACKET, htons (type))) == -1) {
#if 0
		perror("socket");
		printf("socket err\n");
#endif	
		return -1;
	}
	
	if(setsockopt (*s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval)) == -1) {
#if 0
		perror("setsockopt");
		printf("setsockopt err\n");
#endif	
		return -1;
    }
}

