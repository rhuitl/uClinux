/*
 *
 *	portfw - Port Forwarding Table Editing
 *
 * 	$Id: portfw.c,v 1.6 1998/08/29 00:08:11 jjo Exp jjo $   
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
 *		1.2	Changed line cmds to ipfwadm-like, adapt to new ip_masq API -- Juanjo
 *              1.1     Renamed to ipportfw, added address specific forwarding
 *                      with the "-t" and "-u" options and added a new option "-L"
 *		1.0	Initial release
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
#include <linux/ip_masq.h>

#include "ipmasqadm.h"
#include "ipmasqctl.h"

#define IPPROTO_NONE	65535
#define IP_PORTFW_DEF_PREF 10

int do_setsockopt(int cmd, struct ip_masq_ctl *m, int mlen);
void exit_error(int status, char *msg);
void exit_display_help(void);
int list_forwarding(int);

static const char *modname;

int masqmod_main(int argc, const char *argv[])
{
	int c;
	int command = IP_MASQ_CMD_NONE;
	struct ip_masq_ctl mctl;
#define pfw mctl.u.portfw_user
	struct sockaddr_in local_sin;
	struct sockaddr_in redir_sin;
	int tmp;
	int nonames = 0;

	memset (&local_sin, 0, sizeof (local_sin));
	memset (&redir_sin, 0, sizeof (local_sin));
	pfw.protocol = IPPROTO_NONE;
	pfw.raddr = 0;
	pfw.rport = 0;
	pfw.laddr = 0;
	pfw.lport = 0;
	pfw.pref  = IP_PORTFW_DEF_PREF;

	modname = argv[0];

	while ((c = getopt(argc, (char**) argv, "adflnP:R:L:p:h")) != -1)
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
		case 'f':
			if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_FLUSH;
			break;
                case 'l':
                        if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_LIST;
			break;

		case 'n':
			nonames++;
			break;

		case 'P':
			if (pfw.protocol != IPPROTO_NONE)
				exit_error(2, "multiple protocols specified");

			switch (*optarg) {
				case 't':
					pfw.protocol = IPPROTO_TCP;
					break;
				case 'u':
					pfw.protocol = IPPROTO_UDP;
					break;
				default:
					exit_error(2, "invalid protocol specified");
			}
			break;
		case 'L':
			if (local_sin.sin_addr.s_addr||local_sin.sin_port)
				exit_error(2, "multiple local address/port specified");
			tmp = optind-1;
			tmp = parse_addressport(argv+tmp, argc-tmp, &local_sin, nonames);
			if (tmp!=2)
				exit_error(2, "illegal local address/port specified");
			optind += tmp -1;
			break;
		case 'R':
			if (redir_sin.sin_addr.s_addr||redir_sin.sin_port)
				exit_error(2, "multiple destinations specified");
			tmp = optind-1;
			tmp = parse_addressport(argv+tmp, argc-tmp, &redir_sin, nonames);

			if (tmp != 2)
				exit_error(2, "illegal destination specified");
			optind += tmp -1;
			break;
                case 'p':
                        pfw.pref = atoi(optarg);
                        if (pfw.pref <= 0)
                                exit_error(2, "illegal preference value specified");
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

	pfw.rport = redir_sin.sin_port;
	pfw.raddr = redir_sin.sin_addr.s_addr;
	pfw.lport = local_sin.sin_port;
	pfw.laddr = local_sin.sin_addr.s_addr;
	if (command == IP_MASQ_CMD_NONE)
		exit_display_help();

	else if (command == IP_MASQ_CMD_ADD &&
		(pfw.protocol == IPPROTO_NONE || pfw.lport == 0 ))
#if 0
		 || pfw.rport == 0 || pfw.raddr == 0))
#endif
		exit_error(2, "insufficient options specified");

	else if (command == IP_MASQ_CMD_DEL &&
		(pfw.protocol == IPPROTO_NONE || pfw.lport == 0))
		exit_error(2, "insufficient options specified");

#if 0
	else if (command == IP_MASQ_CMD_DEL &&
		 (pfw.rport != 0 || pfw.raddr != 0))
		exit_error(2, "incompatible options specified");
#endif        

	else if ((command == IP_MASQ_CMD_FLUSH || command == IP_MASQ_CMD_LIST) &&
		 (pfw.protocol != IPPROTO_NONE || pfw.lport != 0 ||
		  pfw.rport != 0 || pfw.raddr != 0))
		exit_error(2, "incompatible options specified");

        if (command == IP_MASQ_CMD_LIST) {
		/*	Just "peek" for kernel module  */
		do_setsockopt(IP_MASQ_CMD_NONE, &mctl, sizeof(mctl));
		return list_forwarding(nonames);
	}
                
	return(do_setsockopt(command, &mctl, sizeof (mctl)));
}

int do_setsockopt(int cmd, struct ip_masq_ctl *m, int mlen)
{
	static int sockfd = -1;
	int ret;

	if (sockfd == -1) {
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			perror("portfw: socket creation failed");
			exit(1);
		}
	}
	
	/* This is a masq-mod target op */
	m->m_target = IP_MASQ_TARGET_MOD;
	
	/* This is the target module name */
	strncpy(m->m_tname, modname, sizeof(m->m_tname));

	/* This is the command */
	m->m_cmd = cmd;

	/* Here we go ... */
	ret = setsockopt(sockfd, IPPROTO_IP, IP_FW_MASQ_CTL , (void *) m, mlen);
	if (ret)
		perror("portfw: setsockopt failed");

	return ret;
}


void exit_error(int status, char *msg)
{
	fprintf(stderr, "%s: %s\n", modname, msg);
	exit(status);
}

int list_forwarding(int nm)
{
   char buffer[256];
   int lnum = 0;
   char p_name[10];
   char la_name[80];
   char ra_name[80];
   char ls_name[16];
   char rs_name[16];
   unsigned int hladdr, hlport;
   unsigned int hraddr, hrport;
   int pref_cnt, pref;
   FILE *handle = NULL;
   const char *proc_names[] = {
	   "/proc/net/ip_masq/portfw",
	   "/proc/net/ip_portfw",
	   NULL
   };
   const char **proc_name = proc_names;

   for (;*proc_name;proc_name++) {
	handle = fopen(*proc_name, "r");
	if (handle) 
		break;
	fprintf(stderr, "Could not open \"%s\"\n", *proc_name);
   }

   if (!handle) {
	   fprintf(stderr, "Check if you have enabled portforwarding\n");
	   return 1;
   }

   /*
    *	Line format:
    *	Prot LAddr    LPort > RAddr    RPort PrCnt  Pref               
    *	TCP  C0A80210    23 > C0A8020B    56    10    10               
    *
    */

   while (!feof(handle))
       if (fgets(buffer, sizeof(buffer), handle)) {
	   if (lnum) {
		pref_cnt = pref = -1;
		sscanf(buffer, "%s %x %d > %x %d %d %d", 
			p_name, 
			&hladdr, &hlport,
			&hraddr, &hrport,
			&pref_cnt, &pref);

		printf("%-4s %-20s %-20s %8s %8s %5d %5d\n", 
			p_name, 
			addr_to_name(htonl(hladdr), la_name, sizeof(la_name), nm),
			addr_to_name(htonl(hraddr), ra_name, sizeof(ra_name), nm),
			serv_to_name(htons(hlport), ls_name, sizeof(ls_name), nm),
			serv_to_name(htons(hrport), rs_name, sizeof(rs_name), nm),
			pref_cnt, 
			pref);
	   } else {
		printf("%-4s %-20s %-20s %8s %8s %5s %5s\n", 
		   	"prot",
			"localaddr", "rediraddr",
			"lport", "rport",
			"pcnt", "pref");
	   }
	   lnum++;
       }
   fclose(handle);
   return 0;

}

void exit_display_help(void)
{
	printf(
"Usage: %s -a -P PROTO -L LADDR LPORT -R RADDR RPORT [-p PREF] add entry\n"
"       %s -d -P PROTO -L LADDR LPORT [-R RADDR RPORT]         delete entry\n"
"       %s -f                                                  clear table\n"
"       %s -l                                                  list table\n"
"       %s <args> -n                                           no names\n\n"
"PROTO is the protocol, can be \"tcp\" or \"udp\"\n"
"LADDR is the local interface receiving packets to be forwarded.\n"
"LPORT is the port being redirected.\n"
"RADDR is the remote address.\n"
"RPORT is the port being redirected to.\n"
"PREF  is the preference level (load balancing, default=%d)\n",
               modname, modname, modname, modname, modname,
               IP_PORTFW_DEF_PREF);

	exit(0);
}
