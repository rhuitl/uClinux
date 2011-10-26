/* loattach.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include <fcntl.h>
#include <linux/sockios.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/route.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>

int main(int argc, char*argv[])
{
	int i,f;
	char *p;
	FILE *fp;
	char ** a;
	struct ifreq ifr;
	struct sockaddr_in*in;
	struct rtentry rt;
	char * dev = "lo";
	struct termios tty;
	int speed;

	open_raw_socket();

        setifaddr(dev, "127.0.0.1");
        setifflags(dev, IFF_UP | IFF_RUNNING | IFF_LOOPBACK);

        addroute(dev, RTF_UP/* | RTF_HOST*/,	
        	"127.0.0.0" /* dest net */,
        	"255.0.0.0" /* netmask */,
        	0 /* gateway */);
        
        close_raw_socket();
}
