/*
 * @(#) pfkey socket manipulator/observer
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: pf_key.c,v 1.5 2002/03/08 21:44:04 rgb Exp $
 *
 */

/* 
 * This program opens a pfkey socket and prints all messages that it sees.
 *
 * This can be used to diagnose problems.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <sys/socket.h>

#include <sys/types.h>
#include <stdint.h>
#include <freeswan.h>
#include <pfkeyv2.h>
#include <pfkey.h>

char *progname;
char me[] = "ipsec pf_key";
extern unsigned int pfkey_lib_debug; /* used by libfreeswan/pfkey_v2_build */
uint32_t pfkey_seq = 0;
int pfkey_sock;

static void
Usage(char *progname)
{
	fprintf(stderr, "%s: Usage: %s [--help]\n"
		"\tby default listens for AH, ESP, IPIP and IPCOMP\n"
		"\t--ah       listen for AH messages\n"
		"\t--esp      listen for ESP messages\n"
		"\t--ipip     listen for IPIP messages\n"
		"\t--ipcomp   listen for IPCOMP messages\n",
		progname, progname);
	exit(1);
}

void
pfkey_register(uint8_t satype) {
	/* for registering SA types that can be negotiated */
	int error = 0;
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;

	pfkey_extensions_init(extensions);
	if((error = pfkey_msg_hdr_build(&extensions[0],
					SADB_REGISTER,
					satype,
					0,
					++pfkey_seq,
					getpid()))) {
		fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}
	if((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
		fprintf(stderr, "%s: Trouble building pfkey message, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	if(write(pfkey_sock, pfkey_msg,
		 pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN) !=
	   pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN) {
		/* cleanup code here */
		fprintf(stderr, "%s: Trouble writing to channel PF_KEY.\n", progname);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
}

int
main(int argc, char *argv[])
{
	int opt;
	int readlen;
	unsigned char pfkey_buf[256];
	struct sadb_msg *msg;

	static int ah_register;
	static int esp_register;
	static int ipip_register;
	static int ipcomp_register;

	static struct option long_options[] =
	{
		{"help",        no_argument, 0, 'h'},
		{"version",     no_argument, 0, 'v'},
		{"ah",          no_argument, &ah_register, 1},
		{"esp",         no_argument, &esp_register, 1},
		{"ipip",        no_argument, &ipip_register, 1},
		{"ipcomp",      no_argument, &ipcomp_register, 1},
	};

	ah_register   = 0;
	esp_register  = 0;
	ipip_register = 0;
	ipcomp_register=0;
	
	progname = argv[0];
	if(strrchr(progname, '/')) {
		progname=strrchr(progname, '/')+1;
	}
	
	while((opt = getopt_long(argc, argv, "hv",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		case 'h':
			Usage(progname);
			break;
		case 'v':
			fprintf(stdout, "%s %s\n", me, ipsec_version_code());
			fprintf(stdout, "See `ipsec --copyright' for copyright information.\n");
			exit(0);
		case '0':
			/* it was a long option with a flag */
			break;
		}
	}
	
	if((pfkey_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0) {
		fprintf(stderr, "%s: failed to open PF_KEY family socket: %s\n",
			progname, strerror(errno));
		exit(1);
	}

	if(ah_register == 0 &&
	   esp_register== 0 &&
	   ipip_register==0 &&
	   ipcomp_register==0) {
		ah_register=1;
		esp_register=1;
		ipip_register=1;
		ipcomp_register=1;
	}

	if(ah_register) {
		pfkey_register(SADB_SATYPE_AH);
	}
	if(esp_register) {
		pfkey_register(SADB_SATYPE_ESP);
	}
	if(ipip_register) {
		pfkey_register(SADB_X_SATYPE_IPIP);
	}
	if(ipcomp_register) {
		pfkey_register(SADB_X_SATYPE_COMP);
	}

	while((readlen = read(pfkey_sock, pfkey_buf, sizeof(pfkey_buf))) > 0) {
		struct sadb_ext *extensions[SADB_EXT_MAX + 1];
		msg = (struct sadb_msg *)pfkey_buf;
		
		/* first, see if we got enough for an sadb_msg */
		if(readlen < sizeof(struct sadb_msg)) {
			printf("%s: runt packet of size: %d (<%d)\n",
			       progname, readlen, sizeof(struct sadb_msg));
			continue;
		}
		
		/* okay, we got enough for a message, print it out */
		printf("\npfkey v%d msg. type=%d seq=%d len=%d pid=%d errno=%d satype=%d\n",
		       msg->sadb_msg_version,
		       msg->sadb_msg_type,
		       msg->sadb_msg_seq,
		       msg->sadb_msg_len,
		       msg->sadb_msg_pid,
		       msg->sadb_msg_errno,
		       msg->sadb_msg_satype);
		
		if(readlen != msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)
		{
			printf("%s: packet size read from socket=%d doesn't equal sadb_msg_len %d * %d; message not decoded\n",
			       progname,
			       readlen, 
			       msg->sadb_msg_len,
			       IPSEC_PFKEYv2_ALIGN);
			continue;
		}
		
		pfkey_lib_debug = PF_KEY_DEBUG_PARSE_STRUCT;
		if (pfkey_msg_parse(msg, NULL, extensions, EXT_BITS_OUT)) {
			printf("%s: unparseable PF_KEY message.\n",
			       progname);
		} else {
			printf("%s: parseable PF_KEY message.\n",
			       progname);
		}
	}
	exit(0);
}
	
/*
 * $Log: pf_key.c,v $
 * Revision 1.5  2002/03/08 21:44:04  rgb
 * Update for all GNU-compliant --version strings.
 *
 * Revision 1.4  2001/11/27 05:19:06  mcr
 * 	added extra newline between packets.
 * 	set pfkey_lib_debug to enum rather than just to "1".
 *
 * Revision 1.3  2001/11/27 03:35:29  rgb
 * Added stdlib *again*.
 *
 * Revision 1.2  2001/11/23 07:23:14  mcr
 * 	pulled up klips2 Makefile and pf_key code.
 *
 * Revision 1.1.2.5  2001/10/23 18:49:12  mcr
 * 	renamed man page to section 8.
 * 	added --ah, --esp, --ipcomp and --ipip to control which
 * 	protocols are printed.
 * 	incomplete messages which include at least an sadb header are printed.
 *
 * Revision 1.1.2.4  2001/10/22 21:50:51  rgb
 * Added pfkey register for AH, ESP, IPIP and COMP.
 *
 * Revision 1.1.2.3  2001/10/21 21:51:06  rgb
 * Bug fixes to get working.
 *
 * Revision 1.1.2.2  2001/10/20 22:45:31  rgb
 * Added check for exact length and a call to message parser to get some
 * idea of the contents of each extension.
 *
 * Revision 1.1.2.1  2001/10/17 23:25:37  mcr
 * 	added "pk_key" program to dump raw kernel pf messages.
 * 	(program is still skeletal)
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
