/*
 *	user - User space masq tunnel control
 *
 *	Author: Juan Jose Ciarlante <jjciarla@raiz.uncu.edu.ar>
 *
 * $Id: user.c,v 0.3 1998/08/29 00:08:11 jjo Exp jjo $
 *
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/param.h>


#include "ipmasqadm.h"
#include "ipmasqctl.h"

#include <linux/ip_masq.h>

#define IPPROTO_NONE	65535
#define IP_MASQ_CMD_NONE	0
static const char *modname;

int do_setsockopt(int cmd, struct ip_masq_ctl *m, int mlen);
void exit_error(int status, char *msg);
void exit_display_help(void);


int masqmod_main(int argc, const char *argv[])
{
	int c;
	int command = IP_MASQ_CMD_NONE;
	struct ip_masq_ctl mctl;
#define ums mctl.u.user
	struct sockaddr_in m_sin, s_sin, d_sin;
	int tmp;
	int nonames = 0;

	memset (&m_sin, 0, sizeof (m_sin));
	memset (&d_sin, 0, sizeof (d_sin));
	memset (&s_sin, 0, sizeof (s_sin));
	memset (&ums, 0, sizeof (ums));
	ums.protocol = IPPROTO_NONE;

	modname = argv[0];

	while ((c = getopt(argc, (char**) argv, "adsgnP:M:D:S:t:h")) != -1)
		switch (c) {
			case 'a':
				if (command != IP_MASQ_CMD_NONE)
					exit_error(2, "multiple commands specified");
				command = IP_MASQ_CMD_ADD;
				break;
			case 'd':
				if (command != IP_MASQ_CMD_NONE)
					exit_error(2, "multiple commands specified");
				command = IP_MASQ_CMD_DEL;
				break;
			case 's':
				if (command != IP_MASQ_CMD_NONE)
					exit_error(2, "multiple commands specified");
				command = IP_MASQ_CMD_SET;
				break;
			case 'g':
				if (command != IP_MASQ_CMD_NONE)
					exit_error(2, "multiple commands specified");
				command = IP_MASQ_CMD_GET;
				break;

			case 'n':
				nonames++;
				break;

			case 'P':
				if (ums.protocol != IPPROTO_NONE)
					exit_error(2, "multiple protocols specified");

				switch (*optarg) {
					case 't':
						ums.protocol = IPPROTO_TCP;
						break;
					case 'u':
						ums.protocol = IPPROTO_UDP;
						break;
					default:
						exit_error(2, "invalid protocol specified");
				}
				break;
			case 'M':
				if (m_sin.sin_addr.s_addr||m_sin.sin_port)
					exit_error(2, "multiple [M]asq specified");
				tmp = optind-1;
				tmp = parse_addressport(argv+tmp, argc-tmp, &m_sin, nonames);
				if (tmp!=2)
					exit_error(2, "illegal [M]asq address/port specified");
				optind += tmp -1;
				break;
			case 'S':
				if (s_sin.sin_addr.s_addr||s_sin.sin_port)
					exit_error(2, "multiple [S]ource specified");
				tmp = optind-1;
				tmp = parse_addressport(argv+tmp, argc-tmp, &s_sin, nonames);

				if (tmp != 2)
					exit_error(2, "illegal destination specified");
				optind += tmp -1;
				break;
			case 'D':
				if (d_sin.sin_addr.s_addr||d_sin.sin_port)
					exit_error(2, "multiple [D]estinations specified");
				tmp = optind-1;
				tmp = parse_addressport(argv+tmp, argc-tmp, &d_sin, nonames);

				if (tmp != 2)
					exit_error(2, "illegal destination specified");
				optind += tmp -1;
				break;
			case 't':
				ums.timeout = atoi(optarg) * HZ;
				if (ums.timeout <= 0)
					exit_error(2, "illegal timeout value specified");
				break;
			case 'h':
			case '?':
			default:
				exit_display_help();
		}

	if (optind < argc) {
		printf("optind=%d (%s) argc=%d\n", optind, argv[optind-1], argc);
		exit_error(2, "unknown arguments found on commandline");
	}

	if (command == IP_MASQ_CMD_NONE)
		exit_display_help();

	if (ums.protocol == IPPROTO_NONE) {
		exit_error(2,"no protocol specified");
	}

	ums.mport = m_sin.sin_port;
	ums.maddr = m_sin.sin_addr.s_addr;
	ums.dport = d_sin.sin_port;
	ums.daddr = d_sin.sin_addr.s_addr;
	ums.sport = s_sin.sin_port;
	ums.saddr = s_sin.sin_addr.s_addr;

	switch (command) {
		case IP_MASQ_CMD_ADD:
			if (0) 
				exit_error(2, "insufficient options specified");
			break;
		case IP_MASQ_CMD_DEL:
			if ((ums.mport == 0)||(ums.maddr == 0))
				exit_error(2, "insufficient options specified");
			break;
	}

	return(do_setsockopt(command, &mctl, sizeof(mctl)));
}

void exit_error(int status, char *msg)
{
	fprintf(stderr, "%s: %s\n", modname, msg);
	exit(status);
}


int do_setsockopt(int cmd, struct ip_masq_ctl *m, int mlen)
{
	static int sockfd = -1;
	int ret;

	if (sockfd == -1) {
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			perror("user: socket creation failed");
			exit(1);
		}
	}
	
	/* This is a masq-user op */
	m->m_target = IP_MASQ_TARGET_USER;
	
	/* This is the command */
	m->m_cmd = cmd;

	/* Here we go ... */
	ret = setsockopt(sockfd, IPPROTO_IP, IP_FW_MASQ_CTL , (void *) m, mlen);
	if (ret)

		perror("user: setsockopt failed");

	return ret;
}

void exit_display_help(void)
{
	printf(
"Usage: %s -a -P PROTO -M MADDR MPORT -D DADDR DPORT -S DADDR DPORT add entry\n"
"Usage: %s -d -P PROTO -M MADDR MPORT -D DADDR DPORT -S DADDR DPORT del entry\n"
"       %s <args> -n             no names\n"
"       %s <args> -t <timeout>   with this timeout\n\n"
"PROTO is the protocol, can be \"tcp\" or \"udp\"\n"
"MADDR is the external interface address.\n"
"MPORT is the external port.\n"
"SADDR is the source address (internal).\n"
"SPORT is the source port (internal).\n"
"DADDR is the destination address (external).\n"
"DPORT is the destination port (external).\n"
               ,modname, modname, modname, modname);
	exit(0);
}
