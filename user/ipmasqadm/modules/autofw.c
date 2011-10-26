/*
 * IP Autoforward Control Program v0.20
 *
 * Copyright (c) 1996 Richard Lynch
 *
 * Distributed under GPL.
 *
 * This program should be used with conjunction with the Autoforward kernel
 * patch. It establishes and modifies the tables which the kernel uses to
 * automatically add masquerade entries.
 *
 * Please send any comments, bug reports, and suggestions to
 * rlynch@scoot.netis.com
 *
 * 	$Id: autofw.c,v 0.22 1998/08/29 00:08:11 jjo Exp jjo $	
 *
 */
 
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include <ctype.h>
#include <stdio.h>

#include "ipmasqctl.h"
#include "ipmasqadm.h"
#include <linux/ip_masq.h>


int masqmod_main(int argc, const char * argv [])
{
	struct ip_masq_ctl mctl;
#define af mctl.u.autofw_user
	int socket_fd;
	int index;
	int command;
	int verbose;
	short int b1,b2,b3,b4;
	const char *tmp;
	const char *modname;
	int ret;
	
	b1=0;
	b2=0;
	b3=0;
	b4=0;
	verbose=0;
	command=0;
	af.type=0;
	af.low=0;
	af.high=0;
	af.visible=0;
	af.hidden=0;
	af.protocol=0;
	af.lastcontact=0;
	af.where=0;
	af.ctlproto=0;
	af.ctlport=0;
	af.flags=IP_AUTOFW_USETIME | IP_AUTOFW_SECURE;
	af.next=NULL;
	if (argc<2)
	{
		printf("Usage:\n");
		printf("    ipautofw <command> <options>\n\n");
		printf("Valid commands:\n");
		printf("    -A                           add new autoforward entry\n");
		printf("    -D                           delete an autoforward entry\n");
		printf("    -F                           flush the autoforward table\n");
		printf("\nValid options:\n");
		printf("    -r <type> <low> <high>       forwarding on ports <low> to <high> using\n");
		printf("                                 protocol <type> (tcp or udp)\n\n");
		printf("    -h <host>                    IP address of host to receive forwarded\n");
		printf("                                 packets\n\n");
		printf("    -d <type> <low> <high>       specifies a set of ports which will not use\n");
		printf("                                 the default high range (60000+) masquerade\n");
		printf("                                 port area\n\n");
		printf("    -p <type> <visible> <host>:<hidden>\n");
		printf("                                 set up port bouncing from visible host port\n");
		printf("                                 to masqueraded host <host> on port <hidden>,\n");
		printf("                                 protocol <type> (currently not supported)\n\n");
		printf("    -c <type> <port>             specifies a control port and protocol\n\n");
		printf("    -u                           Do _not_ require that a host connect within\n");
		printf("                                 15 seconds of triggering the control port\n\n");
		printf("    -i                           Insecure mode; any host many connect after\n");
		printf("                                 implied by not using the -c option or implied\n");
		printf("                                 by using the -h option\n");
		printf("                                 once the control port has been triggered\n");
		printf("    -v                           Verbose mode\n\n");
		exit(1);
	}
	modname = argv[0];
	switch(argv[1][1])
	{
		case 'A':
			command=IP_MASQ_CMD_ADD;
			break;
		case 'D':
			command=IP_MASQ_CMD_DEL;
			break;
		case 'F':
			command=IP_MASQ_CMD_FLUSH;
			break;
		default:
			printf("Command must be either -A, -D, or -F\n");
			exit(1);
	}
	if (argc>2 && command==IP_MASQ_CMD_FLUSH)
	{
		printf("The flush command does not take options\n");
		exit(1);
	}
	
	for (index=2;index<argc;index++)
	{
		if (*argv[index]=='-')
		{
			switch (argv[index][1])
			{
				case 'r':
					tmp=argv[index+1];
					if (*tmp!='t' && *tmp!='u')
					{
						printf("protocol must be either tcp or udp\n");
						exit(1);
					}
					if (*tmp=='t')
						af.protocol=IPPROTO_TCP;
					else
						af.protocol=IPPROTO_UDP;
					sscanf(argv[index+2],"%hu",&af.low);
					sscanf(argv[index+3],"%hu",&af.high);
					if (af.low==0 || af.high==0 || af.high<af.low)
					{
						printf("Illegal port numbers\n");
						exit(1);
					}
					index+=3;
					if (af.type)
					{
						printf("-r cannot be used in conjunction with -p or -d\n");
						exit(1);
					}
					af.type=IP_FWD_RANGE;
					break;
				case 'd':
					tmp=argv[index+1];
					if (*tmp!='t' && *tmp!='u')
					{
						printf("protocol must be either tcp or udp\n");
						exit(1);
					}
					if (*tmp=='t')
						af.protocol=IPPROTO_TCP;
					else
						af.protocol=IPPROTO_UDP;
					sscanf(argv[index+2],"%hu",&af.low);
					sscanf(argv[index+3],"%hu",&af.high);
					if (af.low==0 || af.high==0 || af.high<af.low)
					{
						printf("Illegal port numbers\n");
						exit(1);
					}
					index+=3;
					if (af.type)
					{
						printf("-d cannot be used in conjunction with -p or -r\n");
						exit(1);
					}
					af.type=IP_FWD_DIRECT;
					break;
				case 'h':
					if (sscanf(argv[index+1],"%hd.%hd.%hd.%hd",&b1,&b2,&b3,&b4)<0)
					{
						printf("Invalid IP address: %s\n",argv[index+1]);
						exit(1);
					}
					af.where=b1+b2*256+b3*256*256+b4*256*256*256;
					af.flags&=IP_AUTOFW_SECURE ^ 0xFFFF;
					index++;
					break;
				case 'p':
					tmp=argv[index+1];
					if (*tmp!='t' && *tmp!='u')
					{
						printf("protocol must be either tcp or udp\n");
						exit(1);
					}
					if (*tmp=='t')
						af.protocol=IPPROTO_TCP;
					else
						af.protocol=IPPROTO_UDP;
					sscanf(argv[index+2],"%hu",&af.visible);
					sscanf(argv[index+3],"%hu.%hu.%hu.%hu:%hu",&b1,&b2,&b3,&b4,&af.hidden);
					af.where=b1+b2*256+b3*256*256+b4*256*256*256;
					if (af.visible==0 || af.hidden==0)
					{
						printf("Illegal port numbers\n");
						exit(1);
					}
					index+=3;
					if (af.type)
					{
						printf("-p cannot be used in conjunction with -r or -d\n");
						exit(1);
					}
					af.type=IP_FWD_PORT;
					break;
				case 'c':
					tmp=argv[index+1];
					if (*tmp!='t' && *tmp!='u')
					{
						printf("Control protocol must be either tcp or udp\n");
						exit(1);
					}
					if (*tmp=='t')
						af.ctlproto=IPPROTO_TCP;
					else
						af.ctlproto=IPPROTO_UDP;
					sscanf(argv[index+2],"%hu",&af.ctlport);
					index+=2;
					break;
				case 'u':
					af.flags&=IP_AUTOFW_USETIME ^ 0xFFFF;
					break;
				case 'i':
					af.flags&=IP_AUTOFW_SECURE ^ 0xFFFF;
					break;
				case 'v':
					verbose=1;
					break;
				default:
					printf("Invalid option: %s\n",argv[index]);
					exit(1);
			}
		}
		else
		{
			printf("Invalid option: %s\n",argv[index]);
		}
	}
	if (af.where && (af.flags & IP_AUTOFW_SECURE) && af.type!=IP_FWD_PORT)
	{
		printf("Cannot use -h in secure mode\n");
	}
	if (!(af.ctlport && af.ctlproto))
	{
		af.flags&=IP_AUTOFW_SECURE ^ 0xFFFF;
	}
	if (af.ctlport && af.ctlproto && !(af.flags & IP_AUTOFW_SECURE))
	{
		printf("-i cannot be specified with a control port\n");
	}
	if (!af.type && command!=IP_MASQ_CMD_FLUSH)
	{
		printf("You must select a type of forwarding (direct, port, or range)\n");
		exit(1);
	}
	if (verbose)
	{
		switch(command)
		{
			case IP_MASQ_CMD_ADD:
				printf("Adding autofwd ");
				break;
			case IP_MASQ_CMD_DEL:
				printf("Deleteing autofwd ");
				break;
			case IP_MASQ_CMD_FLUSH:
				printf("Flushing autoforward table\n");
				break;
		}
		if (command!=IP_MASQ_CMD_FLUSH)
		{
			if (af.type==IP_FWD_DIRECT)
				printf("(direct) ports %hu - %hu\n",af.low,af.high);
			if (af.type==IP_FWD_PORT)
				printf("%s port %hu -> %hd.%hd.%hd.%hd:%hu ",(af.protocol==IPPROTO_TCP ? "tcp" : "udp" ), af.visible,af.where & 255, (af.where >> 8) & 255, (af.where >> 16) & 255, (af.where >> 24) & 255,af.hidden);
			if (af.type==IP_FWD_RANGE)
			{
				printf("%s ports %hu - %hu ",(af.protocol==IPPROTO_TCP ? "tcp" : "udp" ),af.low,af.high);
				if (af.where)
					printf("to fixed host %hd.%hd.%hd.%hd ",af.where & 255, (af.where >> 8) & 255, (af.where >> 16) & 255, (af.where >> 24) & 255);
			}
			if (af.ctlproto && af.ctlport)
				printf("via %s ctl port %hu ",(af.ctlproto==IPPROTO_TCP ? "tcp" : "udp" ),af.ctlport);
				
		}
		if (af.flags & IP_AUTOFW_USETIME)
			printf("U");
		if (af.flags & IP_AUTOFW_SECURE)
			printf("S");
		printf("\n");
	}
	socket_fd=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socket_fd < 0) {
		perror("socket(RAW)");
		exit(1);
	}
	
	/* This is a masq-mod target op */
	mctl.m_target = IP_MASQ_TARGET_MOD;
	
	/* This is the target module name */
	strncpy(mctl.m_tname, modname, sizeof(mctl.m_tname));

	/* This is the command */
	mctl.m_cmd = command;

	/* Here we go ... */
	ret = setsockopt(socket_fd, IPPROTO_IP, IP_FW_MASQ_CTL , (void *) &mctl, sizeof(mctl));
	if (ret)
		perror("autofw: setsockopt failed");

	return ret;
}
