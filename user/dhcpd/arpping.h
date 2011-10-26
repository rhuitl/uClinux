/*
 * arpping .h
 */

#ifndef ARPPING_H
#define ARPPING_H

#define MAC_BCAST_ADDR	"\xff\xff\xff\xff\xff\xff"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


struct arpMsg {
	struct ether_header ethhdr;	/* Ethernet header */
	u_short htype;				/* hardware type (must be ARPHRD_ETHER) */
	u_short ptype;				/* protocol type (must be ETH_P_IP) */
	u_char  hlen;				/* hardware address length (must be 6) */
	u_char  plen;				/* protocol address length (must be 4) */
	u_short operation;			/* ARP opcode */
	u_char  sHaddr[6];			/* sender's hardware address */
	u_char  sInaddr[4];			/* sender's IP address */
	u_char  tHaddr[6];			/* target's hardware address */
	u_char  tInaddr[4];			/* target's IP address */
	u_char  pad[18];			/* pad for min. Ethernet payload (60 bytes) */
};

struct ifinfo {
    char ifname[IFNAMSIZ];
    u_long addr;		/* network byte order */
    u_long mask;		/* network byte order */
    u_long bcast;		/* network byte order */
    u_char haddr[6];
    short flags;
};


/* function prototypes */
int arpping(u_int32_t yiaddr);

#endif
