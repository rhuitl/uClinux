/*
 *
 *	mfw - FW Mark Forwarding Table Editing
 *
 * 	$Id: mfw.c,v 0.1 1998/07/29 17:50:31 jjo Exp jjo $
 *
 *	Author: Juan Jose Ciarlante <jjciarla@raiz.uncu.edu.ar>
 *	        Strongly based on Steve Clark's portfw.
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
 * Fixes:
 *	Juan J. Ciarlante:	allow nul rport => use packet's port
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

#define IP_MARKFW_DEF_PREF 10

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
#define mfw mctl.u.mfw_user
	struct sockaddr_in redir_sin;
	int tmp;
	int nonames = 0;

	memset (&redir_sin, 0, sizeof (redir_sin));
	mfw.fwmark = 0;
	mfw.raddr = 0;
	mfw.rport = 0;
	mfw.flags = 0;
	mfw.pref  = IP_MARKFW_DEF_PREF;

	modname = argv[0];

	while ((c = getopt(argc, (char**) argv, "AEDFSLnm:r:p:h")) != -1)
		switch (c) {
		case 'A':
			if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_ADD;
			break;
		case 'E':
			if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_SET;
			break;
		case 'D':
			if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_DEL;
			break;
		case 'F':
			if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_FLUSH;
			break;
		case 'S':
			if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_SET;
			mfw.flags |= IP_MASQ_MFW_SCHED;
			break;
                case 'L':
                        if (command != IP_MASQ_CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = IP_MASQ_CMD_LIST;
			break;

		case 'n':
			nonames++;
			break;

		case 'm':
			mfw.fwmark = atoi(optarg);
			break;
		case 'r':
			if (redir_sin.sin_addr.s_addr||redir_sin.sin_port)
				exit_error(2, "multiple destinations specified");
			tmp = optind-1;
			tmp = parse_addressport(argv+tmp, argc-tmp, &redir_sin, nonames);

			if (tmp < 1)
				exit_error(2, "illegal destination specified");
			optind += tmp -1;
			break;
                case 'p':
                        mfw.pref = atoi(optarg);

			/*
			 *	pref == 0 marks the entry as un-schedulable
			 */
                        if (mfw.pref < 0)
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

	mfw.rport = redir_sin.sin_port;
	mfw.raddr = redir_sin.sin_addr.s_addr;
	if (command == IP_MASQ_CMD_NONE)
		exit_display_help();

	else if (command == IP_MASQ_CMD_ADD && (mfw.fwmark == 0 ))
#if 0
		 || mfw.rport == 0 || mfw.raddr == 0))
#endif
		exit_error(2, "insufficient options specified");

	else if (command == IP_MASQ_CMD_DEL &&
		(mfw.fwmark == 0))
		exit_error(2, "insufficient options specified");

#if 0
	else if (command == IP_MASQ_CMD_DEL &&
		 (mfw.rport != 0 || mfw.raddr != 0))
		exit_error(2, "incompatible options specified");
#endif        

	else if ((command == IP_MASQ_CMD_FLUSH || command == IP_MASQ_CMD_LIST) &&
		 (mfw.fwmark != 0 || mfw.rport != 0 || mfw.raddr != 0))
		exit_error(2, "incompatible options specified");

        if (command == IP_MASQ_CMD_LIST) {

		/*	Just "peek" for kernel module  */
		do_setsockopt(IP_MASQ_CMD_NONE, &mctl, sizeof(mctl));
		return list_forwarding(nonames);
	}
                
	return(do_setsockopt(command, &mctl, sizeof(mctl)));
}

int do_setsockopt(int cmd, struct ip_masq_ctl *m, int mlen)
{
	int sockfd;
	int ret;

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("mfw: socket creation failed");
		exit(1);
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
		perror("mfw: setsockopt failed");

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
   char ra_name[80];
   char rs_name[16];
   unsigned int fwmark;
   unsigned int hraddr=0, hrport=0;
   int pref_cnt, pref;
   FILE *handle = NULL;
   const char *proc_names[] = {
	   "/proc/net/ip_masq/mfw",
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
	   fprintf(stderr, "Check if you have enabled fwmark-forwarding\n");
	   return 1;
   }

   /*
    *	Line format:
    *	FWMark > RAddr    RPort PrCnt  Pref               
    *	1020   > C0A8020B    56    10    10               
    *
    */

   while (!feof(handle))
       if (fgets(buffer, sizeof(buffer), handle)) {
	   if (lnum) {
		pref_cnt = pref = -1;
		sscanf(buffer, "%x > %x %d %d %d", 
			&fwmark, 
			&hraddr, &hrport,
			&pref_cnt, &pref);

		printf("%-8d %-20s %8s %5d %5d\n", 
			fwmark, 
			addr_to_name(ntohl(hraddr), ra_name, sizeof(ra_name), nm),
			serv_to_name(ntohs(hrport), rs_name, sizeof(rs_name), nm),
			pref_cnt, 
			pref);
	   } else {
		printf("%-8s %-20s %8s %5s %5s\n", 
		   	"fwmark",
			"rediraddr",
			"rport",
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
"Usage: %s -A -m FWMARK -r RADDR RPORT [-p PREF] add entry\n"
"       %s -D -m FWMARK [-r RADDR RPORT]         delete entry\n"
"       %s -E -m FWMARK [-r RADDR RPORT]         edit entry\n"
"       %s -S -m FWMARK                          force scheduling\n"
"       %s -F                                    clear table\n"
"       %s -L                                    list table\n"
"       %s <args> -n                             no names\n\n"
"FWMARK is the fwmark being redirected.\n"
"RADDR is the remote address.\n"
"RPORT is the port being redirected to.\n"
"PREF  is the preference level (load balancing, default=%d)\n",
               modname, modname, modname, modname, modname, modname, modname,
               IP_MARKFW_DEF_PREF);

	exit(0);
}
