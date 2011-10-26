/*
 * proxyarp.c	- set up or clear proxyarp routing on a device.
 *
 * This code was taken from pppd-2.2.0e, with some revisions copied
 * from pppd-2.2.0f.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "diald.h"

/* This is in netdevice.h. However, this compile will fail miserably if
   you attempt to include netdevice.h because it has so many references
   to __memcpy functions which it should not attempt to do. So, since I
   really don't use it, but it must be defined, define it now. */

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN 7
#endif

#include <net/if.h>
#include <net/if_arp.h>
/* #include <net/route.h> */

extern int sockfd;		/* socket for doing interface ioctls */

#define MAX_IFS		100

#define FLAGS_GOOD (IFF_UP          | IFF_BROADCAST)
#define FLAGS_MASK (IFF_UP          | IFF_BROADCAST | \
		    IFF_POINTOPOINT | IFF_LOOPBACK  | IFF_NOARP)

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */

#define SET_SA_FAMILY(addr, family)			\
    memset ((char *) &(addr), '\0', sizeof(addr));	\
    addr.sa_family = (family);

/*
 * Make a string representation of a network IP address.
 */
char * ip_ntoa(unsigned int ipaddr)
{
    static char b[64];

    ipaddr = ntohl(ipaddr);

    sprintf(b, "%d.%d.%d.%d",
            (u_char)(ipaddr >> 24),
            (u_char)(ipaddr >> 16),
            (u_char)(ipaddr >> 8),
            (u_char)(ipaddr));
    return b;
}

/*
 * get_ether_addr - get the hardware address of an interface on the
 * the same subnet as ipaddr.
 */

static int get_ether_addr (unsigned int ipaddr, struct sockaddr *hwaddr)
{
    struct ifreq *ifr, *ifend;
    unsigned int ina, mask;
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];
    
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
      {
	syslog(LOG_ERR, "ioctl(SIOCGIFCONF): %m");
	return 0;
      }

    if (debug&DEBUG_PROXYARP)
    	syslog(LOG_INFO, "proxy arp: scanning %d interfaces for IP %s",
		ifc.ifc_len / sizeof(struct ifreq), ip_ntoa(ipaddr));
/*
 * Scan through looking for an interface with an Internet
 * address on the same subnet as `ipaddr'.
 */
    ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
      {
	if (ifr->ifr_addr.sa_family == AF_INET)
	  {
	    ina = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
	    strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
	    if (debug&DEBUG_PROXYARP)
            	syslog(LOG_INFO, "proxy arp: examining interface %s",
			ifreq.ifr_name);
/*
 * Check that the interface is up, and not point-to-point
 * nor loopback.
 */
	    if (ioctl(sockfd, SIOCGIFFLAGS, &ifreq) < 0)
	      {
		continue;
	      }

	    if (((ifreq.ifr_flags ^ FLAGS_GOOD) & FLAGS_MASK) != 0)
	      {
		continue;
	      }
/*
 * Get its netmask and check that it's on the right subnet.
 */
	    if (ioctl(sockfd, SIOCGIFNETMASK, &ifreq) < 0)
	      {
	        continue;
	      }

	    mask = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;
	    if (debug&DEBUG_PROXYARP)
	    	syslog(LOG_INFO, "proxy arp: interface addr %s mask %lx",
			ip_ntoa(ina), ntohl(mask));

	    if (((ipaddr ^ ina) & mask) != 0)
	      {
	        continue;
	      }
	    break;
	  }
      }
    
    if (ifr >= ifend)
      {
        return 0;
      }

    syslog(LOG_INFO, "found interface %s for proxy arp", ifreq.ifr_name);
/*
 * Now get the hardware address.
 */
    memset (&ifreq.ifr_hwaddr, 0, sizeof (struct sockaddr));
    if (ioctl (sockfd, SIOCGIFHWADDR, &ifreq) < 0)
      {
        syslog(LOG_ERR, "SIOCGIFHWADDR(%s): %m", ifreq.ifr_name);
        return 0;
      }

    memcpy (hwaddr,
	    &ifreq.ifr_hwaddr,
	    sizeof (struct sockaddr));

    if (debug&DEBUG_PROXYARP)
    	syslog(LOG_INFO,
	   "proxy arp: found hwaddr %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		(int) ((unsigned char *) &hwaddr->sa_data)[0],
		(int) ((unsigned char *) &hwaddr->sa_data)[1],
		(int) ((unsigned char *) &hwaddr->sa_data)[2],
		(int) ((unsigned char *) &hwaddr->sa_data)[3],
		(int) ((unsigned char *) &hwaddr->sa_data)[4],
		(int) ((unsigned char *) &hwaddr->sa_data)[5],
		(int) ((unsigned char *) &hwaddr->sa_data)[6],
		(int) ((unsigned char *) &hwaddr->sa_data)[7]);
    return 1;
}

/*
 * set_proxyarp - Make a proxy ARP entry for the peer.
 */

int set_proxyarp (unsigned int his_adr)
{
    struct arpreq arpreq;

    memset (&arpreq, '\0', sizeof(arpreq));
/*
 * Get the hardware address of an interface on the same subnet
 * as our local address.
 */
    if (!get_ether_addr(his_adr, &arpreq.arp_ha)) {
	syslog(LOG_ERR, "Cannot determine ethernet address for proxy ARP");
	return 0;
    }
    
    SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
    ((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
    arpreq.arp_flags = ATF_PERM | ATF_PUBL;
    
    if (ioctl(sockfd, SIOCSARP, (caddr_t)&arpreq) < 0) {
	syslog(LOG_ERR, "ioctl(SIOCSARP): %m");
	return 0;
    }

    return 1;
}

/*
 * clear_proxyarp - Delete the proxy ARP entry for the peer.
 */

int clear_proxyarp (unsigned int his_adr)
{
    struct arpreq arpreq;

    memset (&arpreq, '\0', sizeof(arpreq));
    SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
    arpreq.arp_flags = ATF_PERM | ATF_PUBL;

    ((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
    if (ioctl(sockfd, SIOCDARP, (caddr_t)&arpreq) < 0) {
	syslog(LOG_WARNING, "ioctl(SIOCDARP): %m");
	return 0;
    }
    return 1;
}
