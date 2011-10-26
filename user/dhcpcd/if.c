/* $Id: if.c,v 1.6 2001-06-29 06:25:14 philipc Exp $
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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "if.h"
#include "dhcp.h"
#include "error-handler.h"
#ifdef CONFIG_NETtel
#include "ip_nettel.h"
#endif

struct ifinfo Ifbuf;

void
ifReset(char *ifname)
{
	bzero((char *)&Ifbuf, sizeof(Ifbuf));
	strncpy(Ifbuf.ifname, ifname, sizeof(Ifbuf.ifname));
	Ifbuf.addr	= htonl(0);
	Ifbuf.mask	= htonl(0);
	Ifbuf.bcast	= inet_addr("255.255.255.255");
	Ifbuf.flags = IFF_UP | IFF_BROADCAST | IFF_NOTRAILERS | IFF_RUNNING;
	ifConfig(&Ifbuf);
}

void
ifConfig(struct ifinfo * ifinfo)
{
    int					s;
	struct ifreq		ifr;
	struct rtentry		rtent;
	struct sockaddr_in	*p;

	strncpy(ifr.ifr_name, ifinfo->ifname, sizeof(ifr.ifr_name));

	if ( (s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		logSysExit("socket (ifConfig)");
	}
	if ( ioctl(s, SIOCGIFHWADDR, &ifr) < 0 ) {
		logSysExit("ioctl SIOCGIFHWADDR (ifConfig)");
	}
	if ( ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER ) {
		logQuit("ifInit: interface %s is not Ethernet\n", ifr.ifr_name);
	}
	/* save hardware address of the interface
	 */
	bcopy(ifr.ifr_hwaddr.sa_data, ifinfo->haddr, sizeof(ifinfo->haddr));

	/* configure interface
	 */
	p = (struct sockaddr_in *)&(ifr.ifr_addr);
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ifinfo->addr;
	if ( ioctl(s, SIOCSIFADDR, &ifr) < 0 ) {
		logSysExit("ioctl SIOCSIFADDR (ifConfig)");
	}
	p->sin_addr.s_addr = ifinfo->bcast;
	if ( ioctl(s, SIOCSIFBRDADDR, &ifr) < 0 ) {
		logSysExit("ioctl SIOCSIFBRDADDR (ifConfig)");
	}
	p->sin_addr.s_addr = ifinfo->mask;
	if ( ioctl(s, SIOCSIFNETMASK, &ifr) < 0 ) {
		logSysExit("ioctl SIOCSIFNETMASK (ifConfig)");
	}
	ifr.ifr_flags = ifinfo->flags;
	if ( ioctl(s, SIOCSIFFLAGS, &ifr) < 0 ) {
		logSysExit("ioctl SIOCSIFFLAGS (ifConfig)");
	}
	/* set route to the interface
	 */
	bzero((char *)&rtent, sizeof(rtent));

	p = (struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ifinfo->addr & ifinfo->mask;	/* dest. net address */

	if (p->sin_addr.s_addr == 0) {
		p->sin_addr.s_addr = 0xffffffff;
		rtent.rt_flags |= RTF_HOST;
	}

	p = (struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ifinfo->addr;				/* gateway address */

	rtent.rt_dev		= ifinfo->ifname;			/* interface name */
	rtent.rt_metric		= 1;						/* metric (see route.h) */
	rtent.rt_flags		|= RTF_UP;					/* net route */
	if ( ioctl(s, SIOCADDRT, &rtent) < 0 ) {
		logSysExit("ioctl SIOCADDRT (ifConfig)");
	}
	close(s);
}

void
ifDown(struct ifinfo * ifinfo)
{
    int					s;
	struct ifreq		ifr;

	strncpy(ifr.ifr_name, ifinfo->ifname, sizeof(ifr.ifr_name));

	if ( (s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		logSysExit("socket (ifDown)");
	}
	/* down interface
	 */
#if 1
	/*
	 *	I don't understand why you would turn on all flags
	 *	except the interface up when shutting down the line?
	 *	That makes it really hard to use ifconfig to then
	 *	set up the interface... It must be wrong.
	 */
	ifr.ifr_flags = 0;
#else
	ifr.ifr_flags = ~IFF_UP;
#endif
	if ( ioctl(s, SIOCSIFFLAGS, &ifr) < 0 ) {
		logSysExit("ioctl SIOCSIFFLAGS (ifDown)");
	}
	close(s);
}



u_long
getNaturalMask(u_long inaddr)
{
	if ( isClassA(inaddr) ) {
		return inet_addr("255.0.0.0");
	}
	if ( isClassB(inaddr) ) {
		return inet_addr("255.255.0.0");
	}
	if ( isClassC(inaddr) ) {
		return inet_addr("255.255.255.0");
	}
	return htonl(0);
}

u_long
getNaturalBcast(u_long inaddr)
{
	if ( isClassA(inaddr) ) {
		return (inaddr & htonl(0xff000000)) | htonl(0x00ffffff);
	}
	if ( isClassB(inaddr) ) {
		return (inaddr & htonl(0xffff0000)) | htonl(0x0000ffff);
	}
	if ( isClassC(inaddr) ) {
		return (inaddr & htonl(0xffffff00)) | htonl(0x000000ff);
	}
	return htonl(0);
}

#ifndef EMBED

void
saveIfInfo(struct ifinfo *ifbuf)
{
	int		 fd;
	int		 isfailed;
	u_long	 leaseLeft;
	char	 filename[IFNAMSIZ + 128];

	/* set up environmet variable on the attached network interface name
	 */
	if ( setenv("DHCP_DEVICE", ifbuf->ifname, 1) < 0 ) {
		logRet("setenv (saveIfInfo): insufficient space");
	}
	isfailed = 0;
	strcpy(filename, DHCP_CACHE_FILE);
	strcat(filename, ifbuf->ifname);
	if ( (fd = creat(filename, 0644)) < 0 ) {
		logSysRet("creat (saveIfinfo)");
		return;
	}
	if ( write(fd, (const char *)&ifbuf->addr, sizeof(ifbuf->addr)) < 0 ) {
		logSysRet("write (saveIfinfo)");
		isfailed = 1;
	}
	if ( LeaseTime == INFINITE_LEASE_TIME ) {
		leaseLeft = INFINITE_LEASE_TIME;
	} else {
		leaseLeft = ntohl(LeaseTime) - (time(NULL) - ReqSentTime);
	}
	if ( write(fd, (const char *)&leaseLeft, sizeof(leaseLeft)) < 0 ) {
		logSysRet("write (saveIfinfo)");
		isfailed = 1;
	}
	if ( isfailed ) {
		if ( unlink((const char*)filename) < 0 ) {
			logSysRet("unlink (saveIfinfo)");
		}
	}
	close(fd);
}

#endif /* EMBED */

void
getIfInfo(struct ifinfo * ifinfo)
{
    int					s;
	struct ifreq		ifr;

	strcpy(ifr.ifr_name, ifinfo->ifname);
	if ( (s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		logSysExit("socket (getIfInfo)");
	}
	if ( ioctl(s, SIOCGIFHWADDR, &ifr) < 0 ) {
		logSysExit("ioctl SIOCGIFHWADDR (getIfInfo)");
	}
	if ( ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER ) {
		logQuit("getIfInfo: interface %s is not Ethernet\n", ifr.ifr_name);
	}
	/* save hardware address of the interface
	 */
	bcopy(ifr.ifr_hwaddr.sa_data, ifinfo->haddr, sizeof(ifinfo->haddr));

	/* configure interface
	 */
	if ( ioctl(s, SIOCGIFADDR, &ifr) < 0 ) {
		logSysExit("ioctl SIOCGIFADDR (getIfInfo)");
	}
	ifinfo->addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	if ( ioctl(s, SIOCGIFBRDADDR, &ifr) < 0 ) {
		logSysExit("ioctl SIOCGIFBRDADDR (getIfInfo)");
	}
	ifinfo->addr = ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr.s_addr;
	if ( ioctl(s, SIOCGIFNETMASK, &ifr) < 0 ) {
		logSysExit("ioctl SIOCGIFNETMASK (getIfInfo)");
	}
	ifinfo->mask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
	if ( ioctl(s, SIOCGIFFLAGS, &ifr) < 0 ) {
		logSysExit("ioctl SIOCGIFFLAGS (getIfInfo)");
	}
	ifinfo->flags = ifr.ifr_flags;
	close(s);
}

void
setDefRoute(const char *routers, struct ifinfo *ifinfo)
{
	u_long gwAddr;				/* router's IP address (network byte order) */
	int s;
	int i;
	struct rtentry		rtent;
	struct sockaddr_in	*p;

	if ( (s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		logSysExit("socket (setDefRoute)");
	}
	bzero((char *)&rtent, sizeof(rtent));
	p = (struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= 0;	/* dest. net address (default route) */
	p = (struct sockaddr_in *)&rtent.rt_genmask;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= 0;
	p = (struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family		= AF_INET;

	/* verify rouer addresses are correct
	 */
	for ( i = 0; i < *routers/4; ++i ) {
		gwAddr = *((u_long *)(routers+1) + i);
		if ( (gwAddr & ifinfo->mask) == (ifinfo->addr & ifinfo->mask)
				&& (gwAddr != ifinfo->addr)
				&& (gwAddr != 0) ) {
			p->sin_addr.s_addr	= gwAddr;
			rtent.rt_dev		= ifinfo->ifname;	/* interface name */
			rtent.rt_metric		= 1;				/* metric (see route.h) */
			rtent.rt_flags		= RTF_UP|RTF_GATEWAY;	/* dest. is a gateway */
			if ( ioctl(s, SIOCADDRT, &rtent) < 0 ) {
				logSysRet("ioctl SIOCADDRT (setDefRoute)");
			}
			else {
				/* TODO: also verify if the router is alive
				 *  or not by using ping
				 */
				break;
			}
		}
	}
	close(s);
}
	
