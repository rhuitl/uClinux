#include "llip.h"
#include <stdlib.h>
#include <features.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <net/route.h>

#include "llip_utils.h"
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0)
	#define OLD_LINUX_VERSION
#endif

#define LINK_LOCAL_NETADDR	0xA9FE0000	/* 169.254.0.0 */

/***************************************************************** 
  llip - link local IP addressing
   Author : Jared Davison
   Date : 5/2/2001
	Copyright 2000, Lineo.

  This program implements IETF Internet draft by Stuart Cheshire 
  (Apple Computer) 24th November 2000.
  Document: draft-ietf-zeroconf-ipv4-linklocal-01.txt
  

  Change History :
  --------------


*****************************************************************/

#define MAX_CONFLICT_COUNT 50	/* recommended by internet draft */
#define ARP_CHECK_TIMEOUT 3

/* Set a certain interface flag. */
static int set_flag(char *ifname, short flag, int skfd)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
	syslog(LOG_ERR, ("%s: unknown interface: %s\n"), 
		ifname,	strerror(errno));
	return (-1);
    }
    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_flags |= flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
	syslog(LOG_ERR, "SIOCSIFFLAGS : %s\n", strerror(errno));
	return -1;
    }
    return (0);
}

/* Clear a certain interface flag. */
static int clr_flag(char *ifname, short flag, int skfd)
{
    struct ifreq ifr;
    int fd;

    if (strchr(ifname, ':')) {
        /* This is a v4 alias interface.  Downing it via a socket for
	   another AF may have bad consequences. */
	    syslog(LOG_ERR, ("No support for aliased interfaces on this system.\n"));
	    return -1;
    } else
        fd = skfd;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
	syslog(LOG_ERR, ("%s: unknown interface: %s\n"), 
		ifname, strerror(errno));
	return -1;
    }
    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_flags &= ~flag;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
	syslog(LOG_ERR,"SIOCSIFFLAGS");
	return -1;
    }
    return (0);
}


/* returns 0 if succeeds, otherwise != 0 */
int get_hwaddr(char* ifname, char* hwaddr_buf, int skfd)
{
	struct ifreq ifr;	/* interface request struct - if.h */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)
		return (-1);
	else
	{
		memcpy(hwaddr_buf, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
		return 0;
	}
}

int set_address(char* ifname, unsigned long ip, unsigned long netmask, int skfd)
{
	struct ifreq ifr;	/* interface request struct - if.h */
	struct sockaddr_in* addr;
	int result;


/* order is important. set IP address, and then the netmask */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

        addr = (struct sockaddr_in *) &ifr.ifr_addr;
        bzero(addr, sizeof(struct sockaddr_in));
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = ip;
        if ((result=ioctl(skfd, SIOCSIFADDR, &ifr))==-1)
        {
                syslog(LOG_ERR, "llip: ioctl SIOCSIFADDR: %s\n", strerror(errno));
		return -1;
        }
	
	addr = (struct sockaddr_in *) & ifr.ifr_broadaddr;
	bzero(addr, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = ip & netmask | ~netmask;
        if ( ioctl(skfd, SIOCSIFBRDADDR, &ifr) == -1)
	{
		syslog(LOG_ERR, "llip: ioctl SIOCSIFBRDADDR: %s\n", strerror(errno));
		return -1;
	}

	addr = (struct sockaddr_in *) &ifr.ifr_netmask;
	bzero(addr, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = netmask;
	if ((result=ioctl(skfd, SIOCSIFNETMASK, &ifr))==-1)
	{
		syslog(LOG_ERR, "llip: ioctl SIOCSIFNETMASK: %s\n",strerror(errno));
		return -1;
	}

        set_flag(ifname, IFF_UP | IFF_BROADCAST | IFF_NOTRAILERS | IFF_RUNNING | IFF_MULTICAST , skfd);

  /* setting local route - not needed on later kernels  */
#ifdef OLD_LINUX_VERSION
 {
        struct rtentry        rtent;
	struct sockaddr_in    *p;

	memset(&rtent,0,sizeof(struct rtentry));
	p                     =       (struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family         =       AF_INET;
	p->sin_addr.s_addr    =      netmask & ip;
	p                     =       (struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family         =       AF_INET;
	p->sin_addr.s_addr    =       0;
	p                     =       (struct sockaddr_in *)&rtent.rt_genmask;
	p->sin_family         =       AF_INET;
	p->sin_addr.s_addr = netmask;
	rtent.rt_dev  =       ifname;
	rtent.rt_metric     = 1;
	rtent.rt_flags      = RTF_UP;
	if ( ioctl(skfd,SIOCADDRT,&rtent) ) {
		syslog(LOG_ERR,"llip: ioctl SIOCADDRT: %m\n");
		return -2;
	}

	/* add host route 255.255.255.255 through interface */
	p = (struct sockaddr_in *) &rtent.rt_dst;
	p->sin_addr.s_addr = 0xffffffffL;
	p = (struct sockaddr_in *) &rtent.rt_genmask;
	p->sin_addr.s_addr = 0xffffffffL;
	if ( ioctl(skfd,SIOCADDRT,&rtent) ) {
		syslog(LOG_ERR,"llip: ioctl SIOCADDRT: %m\n");
		return -2;
	}

 }
#endif

	return 0;
}

/* makes a link local address based on host address provided.
*/
struct in_addr linklocal_makeaddr(unsigned short host)
{
	return inet_makeaddr((IN_CLASSB_NET & LINK_LOCAL_NETADDR), (IN_CLASSB_HOST & host));
}

/* protect the first and last 256 host addresses so that IP address range is from 
  169.254.1.0 to 169.254.254.255
*/
struct in_addr protect_link_local_range(struct in_addr ip)
{
	unsigned long int host = inet_lnaof(ip) & IN_CLASSB_HOST;
	if (host >> 8 == 0)
		host = 0x100 | (0xff & host);
	else if (host >> 8 == 255)
		host = 0xfe00 | (0xff & host);
	ip = linklocal_makeaddr(host);
	return ip;
}


/****************************************** 
 *	ifname must be a network device eg. eth0, dummy
 *	&& skfd must be an initialised socket into the net kernel
 *   returns 0 if succeeds, otherwise -1 */
int setup_link_local_if(char *ifname, unsigned int *addr_assigned)
{	
	unsigned char if_hwaddr[IFHWADDRLEN];
	struct in_addr ip;
	unsigned short conflict = 0; /* conflict status/counter */
	int arp_result;

        int skfd;       /* socket file descriptor used for net ioctls */

	skfd = socket(AF_INET,SOCK_DGRAM,0);
        if(skfd == -1)
        {
                syslog(LOG_ERR,"socket");
                return -1;
        }

	/* bring up network interface in case it is down */
	set_flag(ifname, IFF_UP | IFF_RUNNING, skfd);

	/* get an initial IP guess based upon the last two digits of the 
	   adapter's MAC address.
	*/
	if (get_hwaddr(ifname, if_hwaddr, skfd))
		return -1;	/* failed */	
	ip = linklocal_makeaddr(if_hwaddr[4] << 8 | if_hwaddr[5]);

	/* ip a rule for the cases where the second last digit of the MAC address is */
	/* violates the link local reservation rules. */
	ip = protect_link_local_range(ip);
	
	/* perform an arp check to see if there is another device using the IP on the network local to the interface */
	while (conflict < MAX_CONFLICT_COUNT && (
		arp_result = llip_arpCheck(ifname, ip.s_addr, if_hwaddr, ARP_CHECK_TIMEOUT))==0) /* try a new address if there are conflicts and 
								   if we haven't tried too many times */
	{		
		conflict++; /* set & increment conflict counter  */

		/* if there is, then use the MAC address as a seed 
		   into the random number generator to find a new IP address */ 

		if (conflict==1)
		{	/* ip based on MAC is already used elsewhere on net so seed rand gen. */
			srandom((unsigned int) if_hwaddr[2]); /* use last 4 bytes of MAC as seed for generator */
	 	}

		if (conflict>0)
		{
			/* the was a conflict with the last ip address chosen so get a new random address */
			ip = protect_link_local_range(linklocal_makeaddr(random()));
		}
	}
	if (arp_result == -1)
	{
		/* error with arp */
		syslog(LOG_ERR,"arp request failed");
		return -1;
	}

	if (conflict < MAX_CONFLICT_COUNT) /* found an IP so clear conflict counter */
		conflict = 0;	

	if (conflict==0)	/* if there's no address conflict then set the IP up */
	{
		/* if successful */
		
		if(set_address(ifname, ip.s_addr, ntohl(IN_CLASSB_NET), skfd)<0)
		{
			syslog(LOG_ERR, "Assignment of IP %s to interface %s failed.\n", inet_ntoa(ip), ifname);
			close(skfd);
			return -1;
		}
		else
			syslog(LOG_INFO,"Assignment of IP %s to interface %s succeeded.\n", inet_ntoa(ip), ifname);

		/* Send out 2 gratuitous ARPs, spaced two seconds apart, containing our new
		   IP address. This should flush out any ARP cache entries on hosts left over
		   from some other host that may previously have been using the same address */

		   llip_sendGratuitousArps(ifname, ip.s_addr, if_hwaddr);
		close(skfd);
		*addr_assigned = ip.s_addr;
		return 0;		
	}
	else 
	{
		syslog(LOG_ERR,"Could not find an unused link-local IP to assign with the allowed number of attempts\n"); 
		close(skfd);
		return -1;
	}	
}

/* returns a socket file descriptor which should be passed into the CheckCollision function */
int SetupCollisionMonitor(void)
{
	/*int s;
	if (llip_openRawSocket(&s, ETH_P_ARP)==-1)
		return -1
	else
		return s;*/
}



