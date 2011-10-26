/*
 *
 *	portfw - Port Forwarding Table Editing v1.11
 *
 *	See the accompanying manual page portfw(8) for information
 *	about proper usage of this program. [ Not yet available ]
 *
 *
 *	Copyright (c) 1997 Steven Clarke
 *	All rights reserved.
 *
 *	Author: Steven Clarke <steven@monmouth.demon.co.uk>
 *
 *		Keble College
 *		Oxford
 *		OX1 3PG
 *
 *		WWW:    http://www.monmouth.demon.co.uk/
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
 *
 *	Change history:
 * 		1.11	Changed things around so that it would work
 *                      under GLIBC
 *              1.1     Renamed to ipportfw, added address specific forwarding
 *                      with the "-t" and "-u" options and added a new option "-L"
 *		1.0	Initial release
 *		
 */

#include "linux/autoconf.h"

#ifdef CONFIG_IP_MASQUERADE_IPPORTFW

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#define __u32 u_int32_t
#define __u16 u_int16_t
#ifdef CONFIG_IP_FIREWALL_CHAINS
#include <linux/ip_fwchains.h>
#else
#include <linux/ip_fw.h>
#endif /*CONFIG_IP_FIREWALL_CHAINS*/


/* These really shouldn't be here as they're kernel dependant
   but glibc leaves us no choice :-( */
#define IP_FW_PORTFW            6

#define IP_PORTFW_ADD           (IP_FW_APPEND | (IP_FW_PORTFW << IP_FW_SHIFT))
#define IP_PORTFW_DEL           (IP_FW_DELETE | (IP_FW_PORTFW << IP_FW_SHIFT))
#define IP_PORTFW_FLUSH         (IP_FW_FLUSH  | (IP_FW_PORTFW << IP_FW_SHIFT))

#define IP_PORTFW_PORT_MIN 1
#define IP_PORTFW_PORT_MAX 60999

#include <sys/param.h>

#define IP_PORTFW_NONE	0
#define IP_PORTFW_LIST	10000
#define IPPROTO_NONE	65535

long string_to_number(char *str, int min, int max);
int parse_addressport(char *name, __u32 *raddr, __u16 *rport);
int do_setsockopt(int cmd, struct ip_portfw_edits *data, int length);
void exit_error(int status, char *msg);
void exit_display_help(void);
void list_forwarding(void);

char *program;
char *version = "v1.11-mbv 2000/02/03";

int main(int argc, char *argv[])
{
	int c;
	int command = IP_PORTFW_NONE;
	struct ip_portfw_edits	pfw;

	pfw.protocol = IPPROTO_NONE;
	pfw.raddr = 0;
	pfw.rport = 0;
	pfw.lport = 0;

	program = argv[0];

	while ((c = getopt(argc, argv, "ADCLt:u:R:h")) != -1)
		switch (c) {
		case 'A':
			if (command != IP_PORTFW_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_PORTFW_ADD;
			break;
		case 'D':
			if (command != IP_PORTFW_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_PORTFW_DEL;
			break;
		case 'C':
			if (command != IP_PORTFW_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_PORTFW_FLUSH;
			break;
                case 'L':
                        if (command != IP_PORTFW_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_PORTFW_LIST;
			break;

		case 't':
		case 'u':
			if (pfw.protocol != IPPROTO_NONE)
				exit_error(2, "multiple protocols specified");
			pfw.protocol = (c == 't' ? IPPROTO_TCP : IPPROTO_UDP);
			if (parse_addressport(optarg, &pfw.laddr, &pfw.lport) == -1)
				exit_error(2, "illegal local address/port specified");
			break;
		case 'R':
			if (pfw.raddr != 0 || pfw.rport != 0)
				exit_error(2, "multiple destinations specified");
			if (parse_addressport(optarg, &pfw.raddr, &pfw.rport) == -1)
				exit_error(2, "illegal destination specified");
			break;
		case 'h':
		case '?':
		default:
			exit_display_help();
		}

        if (optind < argc)
                exit_error(2, "unknown arguments found on commandline");

	if (command == IP_PORTFW_NONE)
		exit_display_help();

	else if (command == IP_PORTFW_ADD &&
		(pfw.protocol == IPPROTO_NONE || pfw.lport == 0 ||
		 pfw.rport == 0 || pfw.raddr == 0))
		exit_error(2, "insufficient options specified");

	else if (command == IP_PORTFW_DEL &&
		(pfw.protocol == IPPROTO_NONE || pfw.lport == 0))
		exit_error(2, "insufficient options specified");

	else if (command == IP_PORTFW_DEL &&
		 (pfw.rport != 0 || pfw.raddr != 0))
		exit_error(2, "incompatible options specified");

	else if ((command == IP_PORTFW_FLUSH || command == IP_PORTFW_LIST) &&
		 (pfw.protocol != IPPROTO_NONE || pfw.lport != 0 ||
		  pfw.rport != 0 || pfw.raddr != 0))
		exit_error(2, "incompatible options specified");

        if (command == IP_PORTFW_LIST)
            list_forwarding();
        else
	    exit(do_setsockopt(command, &pfw, sizeof(pfw)));
}


long string_to_number(char *str, int min, int max)
{
	char *end;
	long number;

	number = strtol(str, &end, 10);
	if (*end == '\0' && end != str) {
		if (min <= number && number <= max)
                        return number;
                else
                        return -1;
        } else
                return -1;
}


int parse_addressport(char *name, __u32 *raddr, __u16 *rport)
{
	char buf[23];	/* xxx.xxx.xxx.xxx/ppppp\0 */
	char *p, *q;
	int onebyte, i;
	long l;

	strncpy(buf, name, sizeof(buf) - 1);
	if ((p = strchr(buf, '/')) == NULL)
		return -1;

	*p = '\0';
	if ((l = string_to_number(p+1, IP_PORTFW_PORT_MIN, IP_PORTFW_PORT_MAX)) == -1)
		return -1;
	else
		*rport = l;

	p = buf;
	*raddr = 0;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return -1;
		else {
			*q = '\0';
			if ((onebyte = string_to_number(p, 0, 255)) == -1)
				return -1;
			else
				*raddr = (*raddr << 8) + onebyte;
		}
		p = q + 1;
	}

	/* we've checked 3 bytes, now we check the last one */
	if ((onebyte = string_to_number(p, 0, 255)) == -1)
		return -1;
	else
		*raddr = (*raddr << 8) + onebyte;
		
	return 0;
}


int do_setsockopt(int cmd, struct ip_portfw_edits *data, int length)
{
	static int sockfd = -1;
	int ret;

	if (sockfd == -1) {
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			perror("ipfwadm: socket creation failed");
			exit(1);
		}
	}
	ret = setsockopt(sockfd, IPPROTO_IP, cmd, (char *) data, length);
	if (ret)
		perror("ipfwadm: setsockopt failed");

	return ret;
}


void exit_error(int status, char *msg)
{
	fprintf(stderr, "%s: %s\n", program, msg);
	exit(status);
}

void list_forwarding(void)
{
   char buffer[256];

   FILE *handle;
   handle = fopen("/proc/net/ip_portfw", "r");
   if (!handle) {
       printf("Could not open /proc/net/ip_portfw\nAre you sure you have Port Forwarding installed?\n");
       exit(1);
   }

   while (!feof(handle))
       if (fgets(buffer, 256, handle))
           puts(buffer);
   fclose(handle);

}

void exit_display_help(void)
{
	printf("%s %s\n\n"
		"Usage: %s -A -[t|u] l.l.l.l/lport -R r.r.r.r/rport  add entry\n"
		"       %s -D -[t|u] l.l.l.l/lport                   delete entry\n"
		"       %s -C                                        clear table\n"
		"       %s -L                                        list table\n\n"
                "l.l.l.l is the local interface receiving packets to be forwarded.\n"
                "r.r.r.r is the remote address.\nlport is the port being redirected.\n"
                "rport is the port being redirected to.\n",
		program, version, program, program, program, program);

	exit(0);
}


#else
#include <stdio.h>

int main() {
	printf("IP Port Forwarding not supported in kernel.\n");
	return 0;
}

#endif /* CONFIG_IP_MASQUERADE_IPPORTFW */

