/* ethattach.c:
 *
 * Copied and hacked from loattach.c which was:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Ethernet setup:
 * Copyright (C) 1999  Greg Ungerer (gerg@snapgear.com)
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

usage(char *name, int rc)
{
	printf("usage: %s --addr x.x.x.x [--mask x.x.x.x] "
		"[--net x.x.x.x] [--gw x.x.x.x] [--if x] [--help]\n", name);
	exit(rc);
}

int main(int argc, char *argv[])
{
        int i,f;
        char *p;
        FILE *fp;
        char ** a;
        struct ifreq ifr;
        struct sockaddr_in *in;
        struct rtentry rt;
        char * dev = "eth0";
        struct termios tty;
        int speed;
        char* ipAddr = NULL;
        char* ipMask  = "255.255.255.0";
        char* ipNet  = NULL;
        char* ipGateway = NULL;

        if (argc > 1) {
            for(i=1; i<argc; i++) {
               if (!strcmp(argv[i], "--addr")) {
                   ipAddr = argv[++i];
               } else if (!strcmp(argv[i], "--net")) {
                   ipNet = argv[++i];
               } else if (!strcmp(argv[i], "--mask")) {
                   ipNet = argv[++i];
               } else if (!strcmp(argv[i], "--gw")) {
                   ipGateway = argv[++i];
               } else if (!strcmp(argv[i], "--if")) {
                   dev = argv[++i];
               } else if (!strcmp(argv[i], "--help")) {
		   usage(argv[0], 0);
               }
            }
        }

        open_raw_socket();

	if ((ipAddr == NULL) && (ipGateway == NULL))
		usage(argv[0], 1);

        printf("%s: address: %s, mask: %s, net: %s, gateway: %s\n",
		dev, ipAddr, ipMask, ipNet, ipGateway);
        setifaddr(dev, ipAddr);
        setifflags(dev, IFF_UP | IFF_RUNNING);

        addroute(dev, RTF_UP/* | RTF_HOST*/,
                ipNet /* dest net */,
                ipMask /* netmask */,
                0 /* gateway */);

	if (ipGateway) {
        	addroute(dev, RTF_UP/* | RTF_HOST*/,
                	"0.0.0.0" /* dest net */,
                	"0.0.0.0" /* netmask */,
                	ipGateway /* gateway */);
	}

        close_raw_socket();

    exit(0);
}

