
/*

    File: ip-lib.c
 
    Copyright (C) 1999,2004 by Wolfgang Zekoll <wzk@quietsche-entchen.de>

    This source is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 1, or (at your option)
    any later version.

    This source is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <signal.h>
#include <syslog.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include "lib.h"
#include "ip-lib.h"
#include "pop3.h"



unsigned int get_interface_info(int pfd, peer_t *sock)
{
	int	size;
	struct sockaddr_in saddr;

	size = sizeof(saddr);
	if (getsockname(pfd, (struct sockaddr *) &saddr, &size) < 0)
		printerror(1, "-ERR", "can't get sockname, error= %s", strerror(errno));

	copy_string(sock->ipnum, (char *) inet_ntoa(saddr.sin_addr), sizeof(sock->ipnum));
	sock->port = ntohs(saddr.sin_port);
	copy_string(sock->name, sock->ipnum, sizeof(sock->name));

	return (sock->port);
}


static void alarm_handler()
{
	return;
}

	/*
	 * This version of openip() was copied+pasted from ftp.proxy -- 28OCT04wzk
	 */

int openip(char *host, unsigned int port, char *srcip, unsigned int srcport)
{
	int	socketd;
	struct sockaddr_in server;
	struct hostent *hostp, *gethostbyname();

	socketd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketd < 0)
		return (-1);
  
  	if (srcip != NULL  &&  *srcip != 0) {
		struct sockaddr_in laddr;

		if (srcport != 0) {
			int	one;

			one = 1;
	 		setsockopt (socketd, SOL_SOCKET, SO_REUSEADDR, (int *) &one, sizeof(one));
			}
 
 		/*
         	 * Bind local socket to srcport and srcip
         	 */

 		memset(&laddr, 0, sizeof(laddr));
 		laddr.sin_family = AF_INET;
 		laddr.sin_port   = htons(srcport);

 		if (srcip == NULL  ||  *srcip == 0)
 			srcip = "0.0.0.0";	/* Can't happen but who cares. */
 		else {
 			struct hostent *ifp;
 
 			ifp = gethostbyname(srcip);
 			if (ifp == NULL)
 				printerror(1, "-ERR", "can't lookup %s", srcip);
 
 			memcpy(&laddr.sin_addr, ifp->h_addr, ifp->h_length);
 	 	 	}
 
 		if (bind(socketd, (struct sockaddr *) &laddr, sizeof(laddr)))
 			printerror(1, "-ERR", "can't bind to %s:%u", srcip, ntohs(laddr.sin_port));
		}


	server.sin_family = AF_INET;
	hostp = gethostbyname(host);
	if (hostp == NULL)
		return (-1);
  
	memcpy(&server.sin_addr, hostp->h_addr, hostp->h_length);
	server.sin_port = htons(port);

	signal(SIGALRM, alarm_handler);
	alarm(10);
	if (connect(socketd, (struct sockaddr *) &server, sizeof(server)) < 0)
		return (-1);

	alarm(0);
	signal(SIGALRM, SIG_DFL);
	
 	return (socketd);
}	

unsigned int getportnum(char *name)
{
	unsigned int port;
	struct servent *portdesc;
	
	if (isdigit(*name) != 0)
		port = atol(name);
	else {
		portdesc = getservbyname(name, "tcp");
		if (portdesc == NULL)
			printerror(1, "-ERR", "service not found: %s", name);

		port = ntohs(portdesc->s_port);
		if (port == 0)
			printerror(1, "-ERR", "port error: %s", name);
		}
	
	return (port);
}

unsigned int get_port(char *server, unsigned int def_port)
{
	unsigned int port;
	char	*p;

	if ((p = strchr(server, ':')) == NULL)
		return (def_port);

	*p++ = 0;
	port = getportnum(p);

	return (port);
}

int bind_to_port(char *interface, unsigned int port)
{
	struct sockaddr_in saddr;
	int	sock;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		printerror(1, "-ERR", "can't create socket: %s", strerror(errno));
	else {
		int	opt;

		opt = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		}


	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port   = htons(port);
	
	if (interface == NULL  ||  *interface == 0)
		interface = "0.0.0.0";
	else {
		struct hostent *ifp;

		ifp = gethostbyname(interface);
		if (ifp == NULL)
			printerror(1, "-ERR", "can't lookup %s", interface);

		memcpy(&saddr.sin_addr, ifp->h_addr, ifp->h_length);
		}
		
		
	if (bind(sock, (struct sockaddr *) &saddr, sizeof(saddr)))
		printerror(1, "-ERR", "can't bind to %s:%u", interface, port);

	if (listen(sock, 5) < 0)
		printerror(1, "-ERR", "listen error:  %s", strerror(errno));

	return (sock);
}

int acceptloop(int sock)
{
	int	connect, pid, len;
	struct sockaddr_in client;

	if (debug != 0)
		;
	else if ((pid = fork()) > 0)
		exit (1);

	if (debug != 0)
		fprintf (stderr, "%u: entering daemon mode ...\n", getpid());

	while (1) {
		len = sizeof(client);
		if ((connect = accept(sock, (struct sockaddr *) &client, &len)) < 0) {
			if (errno == EINTR  ||  errno == ECONNABORTED)
				continue;

			fprintf (stderr, "%u: accept error: %s\n", getpid(), strerror(errno));
			continue;
			}

		if ((pid = fork()) < 0) {
			fprintf (stderr, "%u: can't fork process: %s\n", getpid(), strerror(errno));
			exit (1);
			}
		else if (pid == 0) {
			int optlen;
			struct linger linger;

			linger.l_onoff = 1;
			linger.l_linger = 2;
			optlen = sizeof(linger);
			if (setsockopt(connect, SOL_SOCKET, SO_LINGER, &linger, optlen) != 0)
				fprintf (stderr, "%u: can't set linger\n", getpid());

			dup2(connect, 0);
			dup2(connect, 1);

			close (connect);
			close (sock);

			return (0);
			}

		close(connect);
		}

	if (debug != 0)
		fprintf (stderr, "%u: terminating\n", getpid());

	exit (0);
}


int getpeerinfo(int pfd, char *ipnum, int ipsize, char *name, int namesize, int interface)
{
	int	rc, size;
	struct sockaddr_in saddr;
	struct in_addr *addr;
	struct hostent *hostp = NULL;

	*ipnum = 0;
	size = sizeof(saddr);
	if (interface == 0)
		rc = getpeername(pfd, (struct sockaddr *) &saddr, &size); 
	else
		rc = getsockname(pfd, (struct sockaddr *) &saddr, &size);

	if (rc < 0) {
		if (interface == 0)
			copy_string(ipnum, isatty(pfd) == 0? "127.0.0.2": "127.0.0.1", ipsize - 2);
		else
			copy_string(ipnum, "127.0.0.1", ipsize - 2);

		if (name != NULL)
			copy_string(name, "localhost", namesize);

		return (0);
		}		
		
	copy_string(ipnum, (char *) inet_ntoa(saddr.sin_addr), ipsize);
	if (name != NULL) {
		addr = &saddr.sin_addr,
		hostp = gethostbyaddr((char *) addr,
				sizeof (saddr.sin_addr.s_addr), AF_INET);

		if (hostp == NULL)
			copy_string(name, ipnum, namesize - 2);
		else {
			copy_string(name, hostp->h_name, namesize - 2);
			strlwr(name);
			}
		}

	return (0);
}

