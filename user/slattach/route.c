
/* This file is derived from pppd's sys-linux.c file, and is under
   the following copyright: */

/*
 * sys-linux.c - System-dependent procedures for setting up
 * PPP interfaces on Linux systems
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

/*
 * TODO:
 */

#include <sys/types.h>

/*
 * This is to bypass problems with earlier kernels.
 */

#include <string.h>
#undef  _I386_STRING_H_
#define _I386_STRING_H_
#undef  _LINUX_STRING_H_
#define _LINUX_STRING_H_

/*
 * Continue with the rest of the include sequences.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <memory.h>
#include <utmp.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>

/* This is in netdevice.h. However, this compile will fail miserably if
   you attempt to include netdevice.h because it has so many references
   to __memcpy functions which it should not attempt to do. So, since I
   really don't use it, but it must be defined, define it now. */

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN 7
#endif

#include "../pppd.small/usr.include.net/if.h"
#include "../pppd.small/usr.include.net/ppp_defs.h"
#include "../pppd.small/usr.include.net/if_arp.h"
#include "../pppd.small/usr.include.net/if_ppp.h"
#include "../pppd.small/usr.include.net/route.h"
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pppd.h"
#if 0
#include "fsm.h"
#include "ipcp.h"
#endif

static int initdisc = -1;	/* Initial TTY discipline */
static int prev_kdebugflag     = 0;
static int has_default_route   = 0;
static int has_proxy_arp       = 0;
static int driver_version      = 0;
static int driver_modification = 0;
static int driver_patch        = 0;
static int restore_term        = 0;	/* 1 => we've munged the terminal */
static struct termios inittermios;	/* Initial TTY termios */

int sockfd;			/* socket for doing interface ioctls */

static char *lock_file;

#undef syslog
#define syslog(a,b,c...) ({ printf(b, ## c); })
#undef MAINDEBUG
#define MAINDEBUG(x) syslog x

#define MAX_IFS		6

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
 * path_to_proc - determine the path to the proc file system data
 */

FILE *route_fd = (FILE *) 0;
static char route_buffer [512];

static char *path_to_proc (void);
static int open_route_table (void);
static void close_route_table (void);
static int read_route_table (struct rtentry *rt);
static int defaultroute_exists (void);

/*
 * path_to_proc - find the path to the route tables in the proc file system
 */

static char *path_to_proc (void)
  {
    static char buf[32];
    strcpy(buf, "/proc");
    return buf;
  }

/*
 * close_route_table - close the interface to the route table
 */

static void close_route_table (void)
  {
    if (route_fd != (FILE *) 0)
      {
        fclose (route_fd);
        route_fd = (FILE *) 0;
      }
  }

/*
 * open_route_table - open the interface to the route table
 */

static int open_route_table (void)
  {
    char *path;

    close_route_table();

    path = path_to_proc();
    if (path == NULL)
      {
        return 0;
      }

    strcat (path, "/net/route");
    route_fd = fopen (path, "r");
    if (route_fd == (FILE *) 0)
      {
        syslog (LOG_ERR, "can not open %s: %m", path);
        return 0;
      }
    return 1;
  }

/*
 * read_route_table - read the next entry from the route table
 */

#define delims " \t\n"
static int read_route_table (struct rtentry *rt)
  {
    /*static char delims[] = " \t\n";*/
    char *dev_ptr, *ptr, *dst_ptr, *gw_ptr, *flag_ptr;
	
    memset (rt, '\0', sizeof (struct rtentry));

    for (;;)
      {
	if (fgets (route_buffer, sizeof (route_buffer), route_fd) ==
	    (char *) 0)
	  {
	    return 0;
	  }

	dev_ptr  = strtok (route_buffer, delims); /* interface name */
	dst_ptr  = strtok (NULL,         delims); /* destination address */
	gw_ptr   = strtok (NULL,         delims); /* gateway */
	flag_ptr = strtok (NULL,         delims); /* flags */
    
	if (flag_ptr == (char *) 0) /* assume that we failed, somewhere. */
	  {
	    return 0;
	  }
	
	/* Discard that stupid header line which should never
	 * have been there in the first place !! */
	if (isxdigit (*dst_ptr) && isxdigit (*gw_ptr) && isxdigit (*flag_ptr))
	  {
	    break;
	  }
      }

    ((struct sockaddr_in *) &rt->rt_dst)->sin_addr.s_addr =
      strtoul (dst_ptr, NULL, 16);

    ((struct sockaddr_in *) &rt->rt_gateway)->sin_addr.s_addr =
      strtoul (gw_ptr, NULL, 16);

    rt->rt_flags = (short) strtoul (flag_ptr, NULL, 16);
    rt->rt_dev   = dev_ptr;

    return 1;
  }
#undef delims

/*
 * defaultroute_exists - determine if there is a default route
 */

static int defaultroute_exists (void)
  {
    struct rtentry rt;
    int    result = 0;

    if (!open_route_table())
      {
        return 0;
      }

    while (read_route_table(&rt) != 0)
      {
        if ((rt.rt_flags & RTF_UP) == 0)
	  {
	    continue;
	  }
	 
        if (((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr == 0L)
	  {
	    syslog (LOG_ERR,
		    "ppp not replacing existing default route to %s[%s]",
		    rt.rt_dev,
		    inet_ntoa (((struct sockaddr_in *) &rt.rt_gateway)->
			       sin_addr));
	    result = 1;
	    break;
	  }
	  
      }

    close_route_table();
    return result;
  }

/*
 * sifdefaultroute - assign a default route through the address given.
 */

int sifdefaultroute (int unit, int gateway)
  {
    struct rtentry rt;

    if (has_default_route == 0)
      {
	if (defaultroute_exists())
	  {
	    return 0;
	  }

	memset (&rt, '\0', sizeof (rt));
	SET_SA_FAMILY (rt.rt_dst,     AF_INET);
	SET_SA_FAMILY (rt.rt_gateway, AF_INET);
	((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = gateway;
    
	rt.rt_flags = RTF_UP | RTF_GATEWAY;
	if (ioctl(sockfd, SIOCADDRT, &rt) < 0)
	  {
	    syslog (LOG_ERR, "default route ioctl(SIOCADDRT): %m");
	    return 0;
	  }
      }
    has_default_route = 1;
    return 1;
  }

/*
 * cifdefaultroute - delete a default route through the address given.
 */

int cifdefaultroute (int unit, int gateway)
  {
    struct rtentry rt;

    if (has_default_route)
      {
	memset (&rt, '\0', sizeof (rt));
	SET_SA_FAMILY (rt.rt_dst,     AF_INET);
	SET_SA_FAMILY (rt.rt_gateway, AF_INET);
	((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = gateway;
    
	rt.rt_flags = RTF_UP | RTF_GATEWAY;
	if (ioctl(sockfd, SIOCDELRT, &rt) < 0 && errno != ESRCH)
	  {
	    /*if (still_ppp())
	      {
		syslog (LOG_ERR, "default route ioctl(SIOCDELRT): %m");
		return 0;
	      }*/
	  }
      }
    has_default_route = 0;
    return 1;
  }

/*
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */

int sifproxyarp (int unit, u_int32_t his_adr)
  {
    struct arpreq arpreq;
/*
 * Sometime in the 1.3 series kernels, the arp request added a device name.
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < 66381
    char arpreq_arp_dev[32];
#else
#define  arpreq_arp_dev arpreq.arp_dev
#endif

    if (has_proxy_arp == 0)
      {
	memset (&arpreq, '\0', sizeof(arpreq));
/*
 * Get the hardware address of an interface on the same subnet
 * as our local address.
 */
	if (!get_ether_addr(his_adr, &arpreq.arp_ha, arpreq_arp_dev))
	  {
	    syslog(LOG_ERR, "Cannot determine ethernet address for proxy ARP");
	    return 0;
	  }
    
	SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
	((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
	arpreq.arp_flags = ATF_PERM | ATF_PUBL;
	
	if (ioctl(sockfd, SIOCSARP, (caddr_t)&arpreq) < 0)
	  {
	    syslog(LOG_ERR, "ioctl(SIOCSARP): %m");
	    return 0;
	  }
      }

    has_proxy_arp = 1;
    return 1;
  }

/*
 * cifproxyarp - Delete the proxy ARP entry for the peer.
 */

int cifproxyarp (int unit, u_int32_t his_adr)
  {
    struct arpreq arpreq;

    if (has_proxy_arp == 1)
      {
	memset (&arpreq, '\0', sizeof(arpreq));
	SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
	arpreq.arp_flags = ATF_PERM | ATF_PUBL;
    
	((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
	if (ioctl(sockfd, SIOCDARP, (caddr_t)&arpreq) < 0)
	  {
	    syslog(LOG_WARNING, "ioctl(SIOCDARP): %m");
	    return 0;
	  }
      }
    has_proxy_arp = 0;
    return 1;
  }
     
/*
 * get_ether_addr - get the hardware address of an interface on the
 * the same subnet as ipaddr.
 */

char * ip_ntoa(u_int32_t x) { 
	struct in_addr i;
	i.s_addr = x;
	return inet_ntoa(i);
}

static int local_get_ether_addr (u_int32_t ipaddr, struct sockaddr *hwaddr,
				 char *name, struct ifreq *ifs, int ifs_len)
  {
    struct ifreq *ifr, *ifend, *ifp;
    int i;
    u_int32_t ina, mask;
    struct sockaddr_dl *dla;
    struct ifreq ifreq;
    struct ifconf ifc;
/*
 * Request the total list of all devices configured on your system.
 */    
    ifc.ifc_len = ifs_len;
    ifc.ifc_req = ifs;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
      {
	syslog(LOG_ERR, "ioctl(SIOCGIFCONF): %m");
	return 0;
      }

    MAINDEBUG ((LOG_DEBUG, "proxy arp: scanning %d interfaces for IP %s",
		ifc.ifc_len / sizeof(struct ifreq), ip_ntoa(ipaddr)));
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
            MAINDEBUG ((LOG_DEBUG, "proxy arp: examining interface %s",
			ifreq.ifr_name));
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
	    MAINDEBUG ((LOG_DEBUG, "proxy arp: interface addr %s mask %lx",
			ip_ntoa(ina), ntohl(mask)));

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

    memcpy (name, ifreq.ifr_name, sizeof(ifreq.ifr_name));
    syslog(LOG_INFO, "found interface %s for proxy arp", name);
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

    MAINDEBUG ((LOG_DEBUG,
	   "proxy arp: found hwaddr %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		(int) ((unsigned char *) &hwaddr->sa_data)[0],
		(int) ((unsigned char *) &hwaddr->sa_data)[1],
		(int) ((unsigned char *) &hwaddr->sa_data)[2],
		(int) ((unsigned char *) &hwaddr->sa_data)[3],
		(int) ((unsigned char *) &hwaddr->sa_data)[4],
		(int) ((unsigned char *) &hwaddr->sa_data)[5],
		(int) ((unsigned char *) &hwaddr->sa_data)[6],
		(int) ((unsigned char *) &hwaddr->sa_data)[7]));
    return 1;
  }

int get_ether_addr (u_int32_t ipaddr, struct sockaddr *hwaddr, char *name)
  {
    int ifs_len;
    int answer;
    void *base_addr;
/*
 * Allocate memory to hold the request.
 */    
    ifs_len = MAX_IFS * sizeof (struct ifreq);
    base_addr = (void *) malloc (ifs_len);
    if (base_addr == (void *) 0)
      {
	syslog(LOG_ERR, "malloc(%d) failed to return memory", ifs_len);
	return 0;
      }
/*
 * Find the hardware address associated with the controller
 */    
    answer = local_get_ether_addr (ipaddr, hwaddr, name,
				   (struct ifreq *) base_addr, ifs_len);

    free (base_addr);
    return answer;
  }
