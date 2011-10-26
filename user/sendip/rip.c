/* rip.c - RIP-1 and -2 code for sendip
 * Taken from code by Richard Polton <Richard.Polton@msdw.com>
 * ChangeLog since 2.0 release:
 * 02/12/2001 Only check 1 layer for enclosing UDP header
 * 21/08/2002 Off-by-one fix in -re handling that caused bad things to happen
 * 21/08/2002 htons() and htonl() added where needed
 * ChangeLog since 2.2 release:
 * 24/11/2002 make it compile on archs that care about alignment
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "sendip_module.h"
#include "rip.h"

/* Character that identifies our options
 */
const char opt_char='r';

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	rip_header *rip = malloc(sizeof(rip_header));
	memset(rip,0,sizeof(rip_header));
	ret->alloc_len = sizeof(rip_header);
	ret->data = (void *)rip;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	rip_header *rippack = (rip_header *)pack->data;
	rip_options *ripopt;
	char *p, *q;
	switch(opt[1]) {
	case 'v': /* version */
		rippack->version = (u_int8_t)strtoul(arg, (char **)0, 0);
		pack->modified |= RIP_MOD_VERSION;
		break;
	case 'c': /* command */
		rippack->command = (u_int8_t)strtoul(arg, (char **)0, 0);
		pack->modified |= RIP_MOD_COMMAND;
		break;
	case 'a': /* authenticate */
		if(RIP_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIP-2 packet only has authentication on the first entry.\n");
		}
		pack->modified |= RIP_IS_AUTH;
		pack->data = realloc(pack->data,pack->alloc_len+strlen(arg));
		strcpy((char *)pack->data+pack->alloc_len,arg);
		pack->alloc_len += strlen(arg);
		break;
	case 'e': /* rip entry */
		if(RIP_NUM_ENTRIES(pack)==25) {
			usage_error("Warning: a real RIP packet contains no more than 25 entries.\n");
		}
		RIP_ADD_ENTRY(pack);
		ripopt = RIP_OPTION(pack);
		p=q=arg;
		/* TODO: if arg is malformed, this could segfault */
		while(*(q++)!=':') /* do nothing */; *(--q)='\0';
		rippack->addressFamily= htons((p==q)?2:(u_int16_t)strtoul(p, (char **)0, 0));
		pack->modified |= RIP_MOD_ADDRFAM;
		p=++q; while(*(q++)!=':') /* do nothing */; *(--q)='\0';
		rippack->routeTagOrAuthenticationType=htons((p==q)?0:(u_int16_t)strtoul(p, (char **)0,0));
		pack->modified |= RIP_MOD_ROUTETAG;
		p=++q; while(*(q++)!=':') /* do nothing */; *(--q)='\0';
		ripopt->address=(p==q)?inet_addr("0.0.0.0"):inet_addr(p);
		p=++q; while(*(q++)!=':') /* do nothing */; *(--q)='\0';
		ripopt->subnetMask=(p==q)?inet_addr("255.255.255.0"):inet_addr(p);
		p=++q; while(*(q++)!=':') /* do nothing */; *(--q)='\0';
		ripopt->nextHop=(p==q)?inet_addr("0.0.0.0"):inet_addr(p);
		p=++q; while(*(q++)!='\0') /* do nothing */; *(--q)='\0';
		ripopt->metric=htonl((p==q)?16:(u_int32_t)strtoul(p,(char **)0, 0));
		break;
	case 'd': /* default request */
		if(RIP_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIP-1 or -2 packet does not have any entries in a default request.\n");
		}
		rippack->command = (u_int8_t)1;
		rippack->addressFamily = (u_int16_t)0;
		rippack->routeTagOrAuthenticationType = (u_int16_t)0;
		RIP_ADD_ENTRY(pack);
		ripopt=RIP_OPTION(pack);
		ripopt->address=inet_addr("0.0.0.0");
		ripopt->subnetMask=inet_addr("0.0.0.0");
		ripopt->nextHop=inet_addr("0.0.0.0");
		ripopt->metric=htons((u_int16_t)16);
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	if(hdrs[strlen(hdrs)-1] != 'u') {
		usage_error("Warning: RIP should be contained in a UDP packet\n");
	}

	return TRUE;
}

int num_opts() {
	return sizeof(rip_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return rip_opts;
}
char get_optchar() {
	return opt_char;
}
