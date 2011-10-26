/*
 * w3socket.c
 *
 * Copyright (C) 1998 - 2000 Rasca, Berlin
 * EMail: thron@gmx.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "w3socket.h"

#define EMPTY '\0'
#define INIT_ADDR(addr) (memset((char *)&addr, '\0', sizeof (addr)))

/*
 * convert host name or number into the binary version,
 * returns "-1" on error.
 */
unsigned long
host_addr (char *host)
{
	unsigned long bhost = 0;
	struct hostent *hostp;

	if ((host == NULL) || (*host == EMPTY)) {
		return (INADDR_ANY);
	}
	if ((bhost = inet_addr (host)) > -1) {
		return (bhost);
	}
	if ((hostp = gethostbyname(host)) == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (hostp->h_addrtype != AF_INET) {
		errno = EINVAL;
		return (-1);
	}
	return (*((unsigned long *)hostp->h_addr));
}

/*
 * return the file descriptor
 */
int
bind_port (char *host, int port)
{
	int sd=0;
	struct sockaddr_in addr;
	int one = 1;

	INIT_ADDR(addr);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = host_addr(host);
	if (errno == EINVAL) {
		perror (host);
		return (-1);
	}
	if (sizeof (addr.sin_port) == sizeof(short)) {
		addr.sin_port = htons(port);
	} else {
		addr.sin_port = htonl(port);
	}
	if ((sd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		perror (host);
		return (-1);
	}
#ifdef DEBUG
	printf ("%s, sd=%d host_addr()=%d\n", __FILE__, sd, addr.sin_addr.s_addr);
#endif
	setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
	if (bind (sd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		close (sd);
		perror ("bind()");
		return (-1);
	}
	while (listen (sd, 3) == -1) {
		if (errno != EINTR) {
			return (-1);
		}
	}
	return (sd);
}

/*
 * block until next incoming connection
 */
int
accept_con (int sd)
{
	int nd = -1;
	int len;
	struct sockaddr raddr;

	do {
		nd = accept (sd, &raddr, &len);
	} while ((nd < 1) && (errno == EINTR));

	if (nd < 0) {
		return (-1);
	}
	return (nd);
}

