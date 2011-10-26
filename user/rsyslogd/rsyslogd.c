/****************************************************************************/
/*
 * A small syslog server for receiving syslog off the network
 * Copyright (C) 2004 David McCullough <davidm@snapgear.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

/****************************************************************************/

unsigned short s_port = 514;
unsigned char buffer[2048];

/****************************************************************************/

int
main(int argc, char *argv[])
{
	int s, c, n, on = 1;
	struct sockaddr_in sin, from;
	socklen_t fromlen = sizeof(from);
	fd_set rfds;
	FILE *logfile = stdout;

	while ((c = getopt(argc, argv, "p:f:")) != EOF) {
		switch (c) {
		case 'p':
			s_port = atoi(optarg);
			break;
		case 'f':
			logfile = fopen(optarg, "a");
			if (!logfile) {
				perror("fopen");
				exit(1);
			}
			break;
		default:
			fprintf(stderr, "usage: %s [-p port] [-f filename]\n", argv[0]);
			exit(1);
		}
	}

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		perror("socket");
		exit(1);
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
		perror("setsockopt(SO_REUSEADDR)");
		exit(1);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(s_port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)  {
		perror("bind");
		exit(1);
	}

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		if (select(s + 1, &rfds, NULL, NULL, NULL) <= 0) {
			perror("select");
			break;
		}
		n = (int) recvfrom(s, buffer, sizeof(buffer) - 1, 0,
				(struct sockaddr *)&from, &fromlen);
		if (n == -1) {
			perror("recvfrom");
			break;
		}
		if (n > 0) {
			buffer[n] = '\0';
			fprintf(logfile, "%s %s\n", inet_ntoa(from.sin_addr), buffer);
			fflush(logfile);
		}
	}
	close(s);
	fclose(logfile);
}

/****************************************************************************/
