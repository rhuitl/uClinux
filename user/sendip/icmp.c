/* icmp.c - ICMP support for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.0 release:
 * 02/12/2001: Moved ipv6_csum into here as this is where it is used.
 * 02/12/2001: Merged icmp6csum with ipv6_csum
 * 02/12/2001: Only check one layer of headers for enclosing ipv[46] header
 * 22/01/2002: Include string.h
 * 22/02/2002: Fix alignment problem in icmp*csum
 * ChangeLog since 2.1 release:
 * 16/04/2002: Move ipv6_pseudo_header into ipv6.h so tcp.c and udp.c can get it
 * ChangeLog since 2.4 release:
 * 21/04/2003: Fix errors detected by valgrind
 */

#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "sendip_module.h"
#include "icmp.h"
#include "ipv4.h"
#include "ipv6.h"

/* Character that identifies our options
 */
const char opt_char='c';

static void icmpcsum(sendip_data *icmp_hdr, sendip_data *data) {
	icmp_header *icp = (icmp_header *)icmp_hdr->data;
	u_int16_t *buf = malloc(icmp_hdr->alloc_len+data->alloc_len);
	u_int8_t *tempbuf = (u_int8_t *)buf;
	icp->check = 0;
	if(tempbuf == NULL) {
		fprintf(stderr,"Out of memory: ICMP checksum not computed\n");
		return;
	}
	memcpy(tempbuf,icmp_hdr->data,icmp_hdr->alloc_len);
	memcpy(tempbuf+icmp_hdr->alloc_len,data->data,data->alloc_len);
	icp->check = csum(buf,icmp_hdr->alloc_len+data->alloc_len);
	free(buf);
}

static void icmp6csum(struct in6_addr *src, struct in6_addr *dst,
							 sendip_data *hdr, sendip_data *data) {
	icmp_header *icp = (icmp_header *)hdr->data;
	struct ipv6_pseudo_hdr phdr;

	/* Make sure tempbuf is word aligned */
	u_int16_t *buf = malloc(sizeof(phdr)+hdr->alloc_len+data->alloc_len);
	u_int8_t *tempbuf = (u_int8_t *)buf;
	icp->check = 0;
	if(tempbuf == NULL) {
		fprintf(stderr,"Out of memory: ICMP checksum not computed\n");
		return;
	}
	memcpy(tempbuf+sizeof(phdr), hdr->data, hdr->alloc_len);
	memcpy(tempbuf+sizeof(phdr)+hdr->alloc_len, data->data, data->alloc_len);

	/* do an ipv6 checksum */
	memset(&phdr, 0, sizeof(phdr));
	memcpy(&phdr.source, src, sizeof(struct in6_addr));
	memcpy(&phdr.destination, dst, sizeof(struct in6_addr));
	phdr.ulp_length = htonl(hdr->alloc_len+data->alloc_len);
	phdr.nexthdr = IPPROTO_ICMPV6;
	
	memcpy(tempbuf, &phdr, sizeof(phdr));
	
	icp->check = csum(buf,sizeof(phdr)+hdr->alloc_len+data->alloc_len);
	free(buf);
}

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	icmp_header *icmp = malloc(sizeof(icmp_header));
	memset(icmp,0,sizeof(icmp_header));
	ret->alloc_len = sizeof(icmp_header);
	ret->data = (void *)icmp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	icmp_header *icp = (icmp_header *)pack->data;
	switch(opt[1]) {
	case 't':
		icp->type = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= ICMP_MOD_TYPE;
		break;
	case 'd':
		icp->code = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= ICMP_MOD_CODE;
		break;
	case 'c':
		icp->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= ICMP_MOD_CHECK;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	icmp_header *icp = (icmp_header *)pack->data;
	int i=strlen(hdrs)-1;

	/* Find enclosing IP header and do the checksum */
	if(hdrs[i]=='i') {
		// ipv4
		if(!(headers[i]->modified&IP_MOD_PROTOCOL)) {
			((ip_header *)(headers[i]->data))->protocol=IPPROTO_ICMP;
			headers[i]->modified |= IP_MOD_PROTOCOL;
		}
	} else if(hdrs[i]=='6') {
	   // ipv6
		if(!(headers[i]->modified&IPV6_MOD_NXT)) {
			((ipv6_header *)(headers[i]->data))->ip6_nxt=IPPROTO_ICMPV6;
			headers[i]->modified |= IPV6_MOD_NXT;
		}
	}
		
	if(!(pack->modified&ICMP_MOD_TYPE)) {
		if(hdrs[i]=='6') {
			icp->type=ICMP6_ECHO_REQUEST;
		} else {
			icp->type=ICMP_ECHO;
		}
	}

	if(!(pack->modified&ICMP_MOD_CHECK)) {
		if (hdrs[i] == '6') {
			// ipv6
			struct in6_addr *src, *dst;
			src = (struct in6_addr *)&(((ipv6_header *)(headers[i]->data))->ip6_src);
			dst = (struct in6_addr *)&(((ipv6_header *)(headers[i]->data))->ip6_dst);
			icmp6csum(src, dst, pack, data);
		} else {
			// ipv4 or anything else
			icmpcsum(pack,data);
		}
	}
	return TRUE;
}

int num_opts() {
	return sizeof(icmp_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return icmp_opts;
}
char get_optchar() {
	return opt_char;
}
