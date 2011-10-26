/* net.h: Network interface manipulation 
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#ifndef _NET_H_
#define _NET_H_

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

#ifdef __UC_LIBC__
#include <fcntl.h>
#include <linux/sockios.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/route.h>
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

extern int open_raw_socket(void);
extern int close_raw_socket(void);
extern int setifflags(char *ifname, short flags);
extern int setifaddr(char * device, char * addr);
extern int setifdstaddr(char * device, char * addr);
extern int setifbrdaddr(char * device, char * addr);
extern int setifnetmask(char * device, char * mask);
extern int setifmtu(char * device, int mtu);
extern void addroute(char * device, int flags, char * addr, char * netmask, char * gateway);
extern char * maskaddress(const char * address, const char * mask);
extern int setifhwaddr(const char * device, const char * address);

#endif /*_NET_H_*/
