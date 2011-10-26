/* net.c: Network interface manipulation 
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <termios.h>
#include <string.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#ifdef __UC_LIBC__
#include <linux/sockios.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/route.h>
#include <linux/if.h>
#else
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>

#include "net.h"

#define HAVE_NEW_ADDRT 1

#if HAVE_NEW_ADDRT
#define mask_in_addr(x) (((struct sockaddr_in *)&((x).rt_genmask))->sin_addr.s_addr)
#define full_mask(x) (x)
#else
#define mask_in_addr(x) ((x).rt_genmask)
#define full_mask(x) (((struct sockaddr_in *)&(x))->sin_addr.s_addr)
#endif

extern int skfd;

#ifdef L_openraw
int skfd=-1;
int open_raw_socket(void)
{
	if (skfd != -1)
		close(skfd);
        skfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (skfd==-1)
        	return -1;
        return 0;
}
#endif

#ifdef L_closeraw
int close_raw_socket(void)
{
	if (skfd != -1)
		close(skfd);
	skfd = -1;
	return 0;
}
#endif

#ifdef L_setifflags
int setifflags(char *ifname, short flags)
{
  struct ifreq ifr;
	int i;

#ifdef DEBUG
  printf("Adding flags %x to %s\n", flags, ifname);
#endif
  strcpy(ifr.ifr_name, ifname);
  if ((i=ioctl(skfd, SIOCGIFFLAGS, &ifr)) < 0) {
        fprintf(stdout, "SIOCGIFFLAGS = %d: %s (%d)\n", i, strerror(errno), errno);
	  return(-1);
  }
  ifr.ifr_flags |= flags;
  if ((i=ioctl(skfd, SIOCSIFFLAGS, &ifr)) < 0) {
        fprintf(stdout, "SIOCSIFFLAGS = %d: %s (%d)\n", i, strerror(errno), errno);
        return(-1);
  }
  return(0);
}
#endif

#ifdef L_resetifflags
int resetifflags(char *ifname, short flags)
{
  struct ifreq ifr;
	int i;

#ifdef DEBUG
  printf("Adding flags %x to %s\n", flags, ifname);
#endif
  strcpy(ifr.ifr_name, ifname);
  if ((i=ioctl(skfd, SIOCGIFFLAGS, &ifr)) < 0) {
        fprintf(stdout, "SIOCGIFFLAGS = %d: %s (%d)\n", i, strerror(errno), errno);
	  return(-1);
  }
  ifr.ifr_flags &= ~flags;
  if ((i=ioctl(skfd, SIOCSIFFLAGS, &ifr)) < 0) {
        fprintf(stdout, "SIOCSIFFLAGS = %d: %s (%d)\n", i, strerror(errno), errno);
        return(-1);
  }
  return(0);
}
#endif

#ifdef L_setifaddr
int setifaddr(char * device, char * addr)
{
	int i;
	struct ifreq ifr;
	struct sockaddr_in*in;
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);
	
        in = (struct sockaddr_in*)&ifr.ifr_addr;
        in->sin_family = AF_INET;
        in->sin_port = 0;
        in->sin_addr.s_addr = inet_addr(addr);
        
#ifdef DEBUG
        printf("IFADDR %s -> %s\n", device, addr);
#endif
          
        if ((i=ioctl(skfd, SIOCSIFADDR, &ifr)) < 0)
             fprintf(stdout, "SIOCSIFADDR=%d: %d\n", i, errno);
        errno = 0;
        return 0;
}
#endif

#ifdef L_setifdstaddr
int setifdstaddr(char * device, char * addr)
{
	int i;
	struct ifreq ifr;
	struct sockaddr_in*in;
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);
	
        in = (struct sockaddr_in*)&ifr.ifr_addr;
        in->sin_family = AF_INET;
        in->sin_port = 0;
        in->sin_addr.s_addr = inet_addr(addr);
        
#ifdef DEBUG
        printf("IFDSTADDR %s -> %s\n", device, addr);
#endif
          
        if ((i=ioctl(skfd, SIOCSIFDSTADDR, &ifr)) < 0)
             fprintf(stdout, "SIOCSIFDSTADDR=%d: %d\n", i, errno);
        errno = 0;
        return 0;
}
#endif

#ifdef L_setifbrdaddr
int setifbrdaddr(char * device, char * addr)
{
	int i;
	struct ifreq ifr;
	struct sockaddr_in*in;
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);
	
        in = (struct sockaddr_in*)&ifr.ifr_addr;
        in->sin_family = AF_INET;
        in->sin_port = 0;
        in->sin_addr.s_addr = inet_addr(addr);
        
#ifdef DEBUG
        printf("IFBRDADDR %s -> %s\n", device, addr);
#endif

          
        if ((i=ioctl(skfd, SIOCSIFBRDADDR, &ifr)) < 0)
             fprintf(stdout, "SIOCSIFBRDADDR=%d: %d\n", i, errno);
        errno = 0;
        return 0;
}
#endif

#ifdef L_setifnetmask
int setifnetmask(char * device, char * mask)
{
	int i;
	struct ifreq ifr;
	struct sockaddr_in*in;
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);
	
        in = (struct sockaddr_in*)&ifr.ifr_addr;
        in->sin_family = AF_INET;
        in->sin_port = 0;
        in->sin_addr.s_addr = inet_addr(mask);
        
#ifdef DEBUG
        printf("IFNETMASK %s -> %s\n", device, mask);
#endif
          
        if ((i=ioctl(skfd, SIOCSIFNETMASK, &ifr)) < 0)
             fprintf(stdout, "SIOCSIFNETMASK=%d: %d\n", i, errno);
        errno = 0;
        return 0;
}
#endif

#ifdef L_setifmtu
int setifmtu(char * device, int mtu)
{
	int i;
	struct ifreq ifr;
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);
	ifr.ifr_mtu = mtu;
	
#ifdef DEBUG
        printf("SIFSMTU %s -> %d\n", device, mtu);
#endif
          
        if ((i=ioctl(skfd, SIOCSIFMTU, &ifr)) < 0)
             fprintf(stdout, "SIOCSIFMTU=%d: %d\n", i, errno);
        errno = 0;
        return 0;
}
#endif

#ifdef L_addroute
void addroute(char * device, int flags, char * addr, char * netmask, char * gateway)
{
	struct ifreq ifr;
	struct sockaddr_in*in;
	struct rtentry rt;
	unsigned long mask=0;
	int i;
	
        in = (struct sockaddr_in*)&ifr.ifr_addr;
        in->sin_family = AF_INET;
        in->sin_port = 0;
        in->sin_addr.s_addr = addr ? inet_addr(addr) : 0;

	if (gateway)
		flags |= RTF_GATEWAY;

        /* Clean out the RTREQ structure. */
        memset((char *) &rt, 0, sizeof(struct rtentry));
        rt.rt_flags = flags;
        rt.rt_dev = device;
        (*(struct sockaddr_in*)&rt.rt_dst) = *in;
        /*mask_in_addr(rt) = netmask ? inet_addr(netmask) : 0;*/
        
        if (netmask) {
        	in->sin_addr.s_addr = mask = inet_addr(netmask);
	        (*(struct sockaddr_in*)&rt.rt_genmask) = *in;
	}

        in = (struct sockaddr_in*)&ifr.ifr_addr;
        in->sin_family = AF_INET;
        in->sin_port = 0;
        in->sin_addr.s_addr = gateway ? inet_addr(gateway) : 0;
        (*(struct sockaddr_in*)&rt.rt_gateway) = *in;
	
#ifdef DEBUG
	printf("SIOCADDRT %s -> flags: %d, addr: %s, netmask: %s, gateway: %s\n", device, flags, addr, netmask, gateway);
#endif

	if (netmask) {
		if (flags & RTF_HOST)
		printf("Warning: RTF_HOST and netmask don't go together\n");

		if ((~mask) & ((~mask)+1))
			printf("Warning: Bogus netmask\n");

	        in->sin_addr.s_addr = addr ? inet_addr(addr) : 0;
	
		if (in->sin_addr.s_addr & ~mask)
			printf("Warning: netmask doesn't match route address\n");
	}

        if ((i=ioctl(skfd, SIOCADDRT, &rt)) < 0)
             fprintf(stdout, "SIOCADDRT=%d: %d\n", i, errno);
        

}        
#endif

#ifdef L_maskaddress
char * maskaddress(const char * address, const char * mask)
{
	unsigned long a, m;
	struct in_addr i;
	
	a = inet_addr(address);
	m = inet_addr(mask);
	i.s_addr = a & m;
	
	return inet_ntoa(i);
}
#endif

#ifdef L_setifhwaddr
int setifhwaddr(const char * device, const char * addr)
{
	int i;
	unsigned char hw[6];
	struct ifreq ifr;
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);

	for(i=0;addr && (i<6);i++) {
		char * next;
		hw[i] = strtol(addr, &next, 16) & 0xff;
		if (next)
			addr = next + 1;
		else
			addr = 0;
	}
	
	/* parse error */
	if (i!=6)
		return -1;

#ifdef DEBUG
        printf("IFHWADDR %s -> %s (", device, addr);

	for(i=0;i<6;i++) {
		printf("%02.2x", hw[i]);
		if (i<5)
			printf(":");
	}
	printf(")\n");
#endif

	ifr.ifr_hwaddr.sa_family = AF_INET;
	memcpy(ifr.ifr_hwaddr.sa_data, &hw, 6);
          
        if ((i=ioctl(skfd, SIOCSIFHWADDR, &ifr)) < 0)
             fprintf(stdout, "SIOCSIFHWADDR=%d: %d\n", i, errno);
        errno = 0;
        return 0;
}
#endif
