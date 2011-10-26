/* ripng.c - RIPng (version 1) code for sendip
 * Created by hacking rip code
 * ChangeLog since 2.2 release:
 * 15/10/2002 Read the spec
 * 24/11/2002 Made it compile on archs needing alignment
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "sendip_module.h"
#include "ripng.h"

/* Character that identifies our options
 */
const char opt_char='R';

static struct in6_addr inet6_addr(char *hostname) {
	struct hostent *host = gethostbyname2(hostname,AF_INET6);
	struct in6_addr ret;
	if(host==NULL) {
		fprintf(stderr,"RIPNG: Couldn't get address for %s defaulting to loopback",hostname);
		return in6addr_loopback;
	}
	if(host->h_length != sizeof(struct in6_addr)) {
		fprintf(stderr,"RIPNG: IPV6 address is the wrong size: defaulting to loopback");
		return in6addr_loopback;
	}
	memcpy(&ret,host->h_addr,sizeof(ret));
	return ret;
}

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	ripng_header *rip = malloc(sizeof(ripng_header));
	memset(rip,0,sizeof(ripng_header));
	ret->alloc_len = sizeof(ripng_header);
	ret->data = (void *)rip;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	ripng_header *rippack = (ripng_header *)pack->data;
	ripng_entry *ripopt;
	char *p, *q;
	switch(opt[1]) {
	case 'v': /* version */
		rippack->version = (u_int8_t)strtoul(arg, (char **)0, 0);
		pack->modified |= RIPNG_MOD_VERSION;
		break;
	case 'c': /* command */
		rippack->command = (u_int8_t)strtoul(arg, (char **)0, 0);
		pack->modified |= RIPNG_MOD_COMMAND;
		break;
	case 'r': /* reserved */
		rippack->res = htons((u_int16_t)strtoul(arg, (char **)0, 0));
		pack->modified |= RIPNG_MOD_RESERVED;
		break;
		/*
	case 'a': / * authenticate * /
		if(RIPNG_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIP-2 packet only has authentication on the first entry.\n");
		}
		pack->modified |= RIP_IS_AUTH;
		pack->data = realloc(pack->data,pack->alloc_len+strlen(arg));
		strcpy(pack->data+pack->alloc_len,arg);
		pack->alloc_len += strlen(arg);
		break;
		*/
	case 'e': /* rip entry */
		RIPNG_ADD_ENTRY(pack);
		ripopt = RIPNG_ENTRY(pack);
		p=q=arg;
		/* TODO: if arg is malformed, this could segfault */
		while(*(q++)!='/') /* do nothing */; *(--q)='\0';
		ripopt->prefix = (p==q)?in6addr_any:inet6_addr(p);

		p=++q; while(*(q++)!='/') /* do nothing */; *(--q)='\0';
		ripopt->tag=htons( (p==q)?0:(u_int16_t)strtoul(p, (char **)0,0));

		p=++q; while(*(q++)!='/') /* do nothing */; *(--q)='\0';
		ripopt->len=(p==q)?(u_int8_t)128:(u_int8_t)strtoul(p, (char **)0,0);

		p=++q; while(*(q++)!='\0') /* do nothing */; *(--q)='\0';
		ripopt->metric=(p==q)?(u_int8_t)16:(u_int8_t)strtoul(p,(char **)0, 0);
		break;
	case 'd': /* default request */
		if(RIPNG_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIPng packet does not have any other entries in a default request.\n");
		}
		rippack->command = (u_int8_t)1;
		rippack->version = (u_int8_t)1;
		rippack->res = (u_int16_t)0;
		pack->modified|=RIPNG_MOD_COMMAND|RIPNG_MOD_VERSION|RIPNG_MOD_RESERVED;
		RIPNG_ADD_ENTRY(pack);
		ripopt=RIPNG_ENTRY(pack);
		ripopt->prefix=in6addr_any;
		ripopt->tag=(u_int16_t)0;
		ripopt->len=(u_int8_t)0;
		ripopt->metric=htons((u_int16_t)16);
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	if(hdrs[strlen(hdrs)-1] != 'u') {
		usage_error("Warning: RIPng should be contained in a UDP packet\n");
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
