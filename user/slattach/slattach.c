/* slattach.c: Bind a SLIP interface, in the same manner as pppd
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
#include <linux/if_eql.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/route.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>
#include <serial.h>

#include "route.h"

static char * program;

int done = 0;
static void sigh(int signo)
{
	signal(signo, sigh);
	done = 1;
}

static void slattach(int fd, const char * me, const char * them, const char * netmask, int timeout)
{
	int i;
	struct ifreq ifr;
	struct sockaddr_in*in;
	struct termios tty;

	printf("%s: attaching SLIP\n", program);

  	printf("slat6\n");
	
	tcgetattr(fd, &tty);
	make_raw_tty(&tty);
	tcsetattr(fd, TCSANOW, &tty);

  	printf("slat7\n");

	alarm(1);
	i = N_SLIP;
	i = ioctl(fd, TIOCSETD, &i);
	if (i)
		printf("TIOCSETD returned %d, errno = %d\n", i, errno);	
	alarm(0);
	
  	printf("slat8\n");

	i = 0;
	i = ioctl(fd, SIOCSIFENCAP, &i);
	if (i)
		printf("SIOCSIFENCAP returned %d, errno = %d\n", i, errno);	

	memset(&ifr, '\0', sizeof(ifr));

	strcpy(ifr.ifr_name, "<none>");
	
	i = ioctl(fd, SIOCGIFNAME, &ifr.ifr_name[0]);
	if (i)
		printf("SIOCGIFNAME returned %d and '%s', errno = %d\n", i, (char*)&ifr.ifr_name[0], errno);

  	printf("slat9\n");
	
        /* Open raw socket */
        open_raw_socket();

  	printf("slat10\n");
        
        setifaddr(ifr.ifr_name, me);

  	printf("slat11\n");

        setifflags(ifr.ifr_name, IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
        
        setifdstaddr(ifr.ifr_name, them);
        setifnetmask(ifr.ifr_name, "255.255.255.255");

        addroute(ifr.ifr_name, RTF_UP | RTF_HOST, them, 
        					0 /* no netmask */, 
        					0 /* no gateway */); 

	if (netmask) {
		unsigned long mask_in = inet_addr(netmask);
		unsigned long me_in = inet_addr(me);
		struct in_addr in_a;
		char * maskedme;
		
		in_a.s_addr = me_in & mask_in;
		maskedme = inet_ntoa(in_a);
		
		printf("my address masked by %s is %s\n",
			netmask, maskedme);
		
		/* masked, perhaps generic route (if netmask is 0.0.0.0)*/
	        addroute(0, 
	        	RTF_UP, 
	        	maskedme /* destination */,
	        	netmask /* netmask */,
	        	them /* gateway */);
	}
	
	close_raw_socket();

	if (timeout < 0) {
		/* sleep till we get killed, one way or another */
		while(!done)
			pause();
	} else {
		struct sockaddr_in sa;
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = inet_addr(them);
		pinger(fd, timeout, (struct sockaddr*)&sa, sizeof(sa));
	}
}

static void usage(void) {
  	fprintf(stderr, 
  "Usage: %s [-a] [-p <port>] [-s <port-settings>] [-t <timeout>] [-m <netmask>] <my-ip> <their-ip>\n"
  "Timeout is time in seconds before link will shut down if other side\n"
  "does not respond to pings.\n"
  "The -a switch adds a proxy-arp entry for this device.\n", 
  program);
  	exit(0);
}

char msg[64];
int main(int argc, char *argv[])
{
	char * port = 0;
	char * settings = 0;
	char * netmask = 0;
	int timeout = -1;
	int arp = 0;
	int fd;
	struct in_addr in;
	char * me;
	char * them;
	
	program = argv[0];
	
  	if (argc<3) {
  		usage();
  	}
  	
  	while ((argc>3) && (argv[1][0] == '-')) {
  		if (argc < 4)
  			usage();
  		switch (argv[1][1]) {
  		case 'p':
  			port = argv[2];
	  		argc-=2;
	  		argv+=2;
  			break;
  		case 't':
  			timeout = atoi(argv[2]);
	  		argc-=2;
	  		argv+=2;
  			break;
  		case 's':
  			settings = argv[2];
	  		argc-=2;
	  		argv+=2;
  			break;
  		case 'm':
  			netmask = argv[2];
	  		argc-=2;
	  		argv+=2;
  			break;
  		case 'a':
  			arp = 1;
  			argc--;
  			argv++;
  			break;
  		default:
  			usage();
  		}
  	}
  	
  	if (argc != 3)
  		usage();
  	
  	printf("slat1\n");
  	
  	me = argv[1];
  	them = argv[2];
  		
  	if (!inet_aton(me, &in))
  		usage();

  	if (!inet_aton(them, &in))
  		usage();
  	

  	printf("slat2\n");
  	
  	if (port) {
  		fd = open(port, O_RDWR|O_NONBLOCK);
  		if (fd == -1)
  			exit(0);
  		if (settings)
	  		setserial(fd, settings);
	  	fcntl(fd, F_SETFL, 0);
  	} else {
  		fd = 0;
  	}

  	printf("slat3\n");
  	
  	/* Print the IP addresses out to the port, in case somebody
  	   needs them. */
  	
  	sprintf(msg, "Client address is %s\n", them);
  	write(fd, msg, strlen(msg));
  	sprintf(msg, "Server address is %s\n", me);
  	write(fd, msg, strlen(msg));
  	
  	signal(SIGHUP, sigh);
  	signal(SIGTERM, SIG_IGN); /* so we don't get shut down easily */

  	printf("slat4\n");
  	
  	if (arp)
  		/* add arp entry so that the remote host is reachable
  		   via the local net. This only works if there is
  		   a local ethernet, and the remote IP address
  		   is within its range */
  		arp = sifproxyarp(0, in.s_addr);

  	printf("slat5\n");

	/* stay attached until we die, due to a signal, the control
	   lines terminating us, or timing out due to a bad connection */
	slattach(fd, me, them, netmask, timeout);

  	if (arp)
  		/* if arp was set up, tear it down */
  		cifproxyarp(0, in.s_addr);
	
	close(fd);
	return 0;
}

