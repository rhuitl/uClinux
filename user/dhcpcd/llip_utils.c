/*
 * llip_arp.c
 *
 * Portions credited to Yoichi Hariguchi
 * 
 * Jared Davison (Lineo) j.davison@moreton.com.au
 */


#include "llip_utils.h"
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#define MAC_BCAST_ADDR  "\xff\xff\xff\xff\xff\xff"
#define GRATUITOUS_ARPS	2
#define GRATUITOUS_ARP_SPACING	2	/* seconds*/

struct arpMsg {
        struct ethhdr ethhdr;                   /* Ethernet header */
        u_short htype;                          /* hardware type (must be ARPHRD_ETHER) */
        u_short ptype;                          /* protocol type (must be ETH_P_IP) */
        u_char  hlen;                           /* hardware address length (must be 6) */
        u_char  plen;                           /* protocol address length (must be 4) */
        u_short operation;                      /* ARP opcode */
        u_char  sHaddr[6];                      /* sender's hardware address */
        u_char  sInaddr[4];                     /* sender's IP address */
        u_char  tHaddr[6];                      /* target's hardware address */
        u_char  tInaddr[4];                     /* target's IP address */
        u_char  pad[18];                        /* pad for min. Ethernet payload (60 bytes) */
};

/* local prototypes */
void llip_mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr,
                 u_long sInaddr, u_char *sHaddr, struct arpMsg *msg);
int llip_openRawSocket (int *s, u_short type);

int llip_sendGratuitousArps(char* device_name, u_long address, unsigned char *source_hw_addr[6]) 
{
	int s;				/* socket */
	struct sockaddr	addr;		/* for interface name */
	int i;	/*counter*/
	struct arpMsg	arp;		/* arp message */

	if (llip_openRawSocket(&s, ETH_P_ARP)==-1)
	{	
		return -1;
	}

	/* send two arps two seconds apart */
	llip_mkArpMsg(ARPOP_REPLY, 0xffffffffU, MAC_BCAST_ADDR, address, (u_char*) source_hw_addr, &arp);
	bzero(&addr, sizeof(addr));
	strncpy(addr.sa_data, device_name, sizeof(addr.sa_data));

	for(i=0; i<GRATUITOUS_ARPS; i++)
	{
		if ( sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0 ) {
#if 0
			syslog(LOG_INFO, "sendto (sendGratuitousArp)");
#endif
			syslog(LOG_INFO, "sendto : ");
			close(s);
			return -1;
		}
		sleep(GRATUITOUS_ARP_SPACING);
	}
	close(s);
	return 0;
}

/*********************************************************
 * Function :  arpCheck
 * retn:        1 addr free
 *               addr used
 *              -1 error
 */
int llip_arpCheck(char* device_name, u_long test_addr, unsigned char *source_hw_addr, long timeout)  {
	int	s;			/* socket */
	int	rv;			/* return value (IP test_addr usage status */
	struct sockaddr addr;		/* for interface name */
	struct arpMsg	arp;
	fd_set			fdset;
	struct timeval	tm;
	time_t			prevTime;

	rv = 1; /* initialise ip to unused status */

	if (llip_openRawSocket(&s, ETH_P_ARP)==-1)
	{
		return -1;
	}
/* we should send up to four probes at two second intervals or until we receive a response to our probe */

	/* send arp probe */
	llip_mkArpMsg(ARPOP_REQUEST, test_addr, MAC_BCAST_ADDR, 0 /* source=0.0.0.0 */, (u_char *) source_hw_addr, &arp);
	bzero(&addr, sizeof(addr));
	strncpy(addr.sa_data, device_name, sizeof(addr.sa_data));

	if ( sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0 ) {
		syslog(LOG_ERR,"sendto (arpCheck): ");
		close(s);
		return -1;
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
			syslog(LOG_INFO,"select (arpCheck)");
#endif
			rv = 0; /* address used */
		}
		if ( FD_ISSET(s, &fdset) ) {
			if (recv(s, &arp, sizeof(arp), 0) < 0 ) {
#if 0
				syslog(LOG_INFO,"recv (arpCheck)");
#endif
				rv = 0; /* address used */
			}

			/* Receive response to our arp probe from a host configured with the IP  */
			if(arp.operation == htons(ARPOP_REPLY) && memcmp(arp.tHaddr, source_hw_addr, 6) == 0 && *((u_int *)arp.sInaddr) == test_addr ) {
				rv = 0; /* address used */
				break;
			}

			/* Watch for other ARP probes for the same address originating from other hosts while
			   waiting for response to our ARP probe. This should help out in the situation
			   where two or more hosts by chance attempt to configure the same IP address.
			   If we receive an ARP probe for the same IP address from another hardware address
			   then we return the fact the address is used */
			if(arp.operation == htons(ARPOP_REPLY) && memcmp(arp.ethhdr.h_dest, MAC_BCAST_ADDR, 6) == 0 && *((u_int *)arp.tInaddr) == test_addr && *((u_int *) arp.sInaddr) == 0 ) {
				rv = 0;  /* address used - race condition caught */
				break;
			}
		}
		timeout -= time(NULL) - prevTime;
		time(&prevTime);
	}
	close(s);
	return rv;
}

void llip_mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr,
		 u_long sInaddr, u_char *sHaddr, struct arpMsg *msg) {
	bzero(msg, sizeof(*msg));
	bcopy(tHaddr, msg->ethhdr.h_dest, 6); /* MAC DA */
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


int llip_openRawSocket (int *s, u_short type) {
	int optval = 1;

	if((*s = socket (AF_INET, SOCK_PACKET, htons (type))) == -1) {
#if 0
		syslog(LOG_ERR,"socket err : %s\n",strerr());
#endif
		return -1;
	}
	
	if(setsockopt (*s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval)) == -1) {
#if 0
		syslog(LOG_ERR,"setsockopt err : %s\n",strerr());
#endif
		return -1;
    }
}


#if 0
/* returns a socket file descriptor which should be passed into the CheckCollision function */
struct collisionMonitor* llip_SetupCollisionMonitor(void)
{
        int s;
        if (openRawSocket(&s, ETH_P_ARP)==-1)
                return NULL;
        else
	{
                return s;
	}
}
struct collisionMonitor {
	int		s;		/* socket for monitoring arps */
	long 		timeout;
	fd_set		fdset;
	struct timeval	tm;
	time_t		prevTime;
}

/* returns 0 if no collision, !=0 for collision */
int llip_CheckCollision(int collision_socket)
{
	/* watch for collisions */
	/* wait arp reply, and check it */
	tm.tv_usec = 0;
	time(&prevTime);
	while ( timeout > 0 ) {
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		tm.tv_sec  = timeout;
		if ( select(s+1, &fdset, (fd_set *)NULL, (fd_set *)NULL, &tm) < 0 ) {
#if 0
			syslog(LOG_INFO,"select (arpCheck)");
#endif
			rv = 0; /* address used */
		}
		if ( FD_ISSET(s, &fdset) ) {
			if (recv(s, &arp, sizeof(arp), 0) < 0 ) {
#if 0
				syslog(LOG_INFO,"recv (arpCheck)");
#endif
				rv = 0; /* address used */
			}

			/* Receive response to our arp probe from a host configured with the IP  */
			if(arp.operation == htons(ARPOP_REPLY) && memcmp(arp.tHaddr, source_hw_addr, 6) == 0 && *((u_int *)arp.sInaddr) == test_addr ) {
				rv = 0; /* address used */
				break;
			}

			/* Watch for other ARP probes for the same address originating from other hosts while
			   waiting for response to our ARP probe. This should help out in the situation
			   where two or more hosts by chance attempt to configure the same IP address.
			   If we receive an ARP probe for the same IP address from another hardware address
			   then we return the fact the address is used */
			if(arp.operation == htons(ARPOP_REPLY) && memcmp(arp.ethhdr.h_dest, MAC_BCAST_ADDR, 6) == 0 && *((u_int *)arp.tInaddr) == test_addr && *((u_int *) arp.sInaddr) == 0 ) {
				rv = 0;  /* address used - race condition caught */
				break;
			}
		}
		timeout -= time(NULL) - prevTime;
		time(&prevTime);
	}

}
#endif
