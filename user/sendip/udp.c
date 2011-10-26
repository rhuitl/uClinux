/* udp.c - UDP code for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.0 release:
 * ChangeLog since 2.1 release:
 * 16/04/2002: Only check one layer of enclosing headers for ip
 * 16/04/2002: Add support for UDP over IPV6
 * ChangeLog since 2.4 release:
 * 21/04/2003: Fix errors found by valgrind
 */

#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "sendip_module.h"
#include "udp.h"
#include "ipv4.h"
#include "ipv6.h"

/* Character that identifies our options
 */
const char opt_char='u';

static void udpcsum(sendip_data *ip_hdr, sendip_data *udp_hdr,
						  sendip_data *data) {
	udp_header *udp = (udp_header *)udp_hdr->data;
	ip_header  *ip  = (ip_header *)ip_hdr->data;
	u_int16_t *buf = malloc(12+udp_hdr->alloc_len+data->alloc_len);
	u_int8_t *tempbuf = (u_int8_t *)buf;
	udp->check=0;
	if(tempbuf == NULL) {
		fprintf(stderr,"Out of memory: UDP checksum not computed\n");
		return;
	}
	/* Set up the pseudo header */
	memcpy(tempbuf,&(ip->saddr),sizeof(u_int32_t));
	memcpy(&(tempbuf[4]),&(ip->daddr),sizeof(u_int32_t));
	tempbuf[8]=0;
	tempbuf[9]=(u_int16_t)ip->protocol;
	tempbuf[10]=(u_int16_t)((udp_hdr->alloc_len+data->alloc_len)&0xFF00)>>8;
	tempbuf[11]=(u_int16_t)((udp_hdr->alloc_len+data->alloc_len)&0x00FF);
	/* Copy the UDP header and data */
	memcpy(tempbuf+12,udp_hdr->data,udp_hdr->alloc_len);
	memcpy(tempbuf+12+udp_hdr->alloc_len,data->data,data->alloc_len);
	/* CheckSum it */
	udp->check = csum(buf,12+udp_hdr->alloc_len+data->alloc_len);
	free(buf);
}

static void udp6csum(sendip_data *ipv6_hdr, sendip_data *udp_hdr,
							sendip_data *data) {
	udp_header *udp = (udp_header *)udp_hdr->data;
	ipv6_header  *ipv6  = (ipv6_header *)ipv6_hdr->data;
	struct ipv6_pseudo_hdr phdr;

	u_int16_t *buf = malloc(sizeof(phdr)+udp_hdr->alloc_len+data->alloc_len);
	u_int8_t *tempbuf = (u_int8_t *)buf;
	udp->check=0;
	if(tempbuf == NULL) {
		fprintf(stderr,"Out of memory: UDP checksum not computed\n");
		return;
	}

	/* Set up the pseudo header */
	memset(&phdr,0,sizeof(phdr));
	memcpy(&phdr.source,&ipv6->ip6_src,sizeof(struct in6_addr));
	memcpy(&phdr.destination,&ipv6->ip6_dst,sizeof(struct in6_addr));
	phdr.ulp_length=IPPROTO_UDP;
	
	memcpy(tempbuf,&phdr,sizeof(phdr));

	/* Copy the UDP header and data */
	memcpy(tempbuf+sizeof(phdr),udp_hdr->data,udp_hdr->alloc_len);
	memcpy(tempbuf+sizeof(phdr)+udp_hdr->alloc_len,data->data,data->alloc_len);

	/* CheckSum it */
	udp->check = csum(buf,sizeof(phdr)+udp_hdr->alloc_len+data->alloc_len);
	free(buf);
}

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	udp_header *udp = malloc(sizeof(udp_header));
	memset(udp,0,sizeof(udp_header));
	ret->alloc_len = sizeof(udp_header);
	ret->data = (void *)udp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	udp_header *udp = (udp_header *)pack->data;
	switch(opt[1]) {
	case 's':
		udp->source = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_SOURCE;
		break;
	case 'd':
		udp->dest = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_DEST;
		break;
	case 'l':
		udp->len = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_LEN;
		break;
	case 'c':
		udp->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_CHECK;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	udp_header *udp = (udp_header *)pack->data;
	
	/* Set relevant fields */
	if(!(pack->modified&UDP_MOD_LEN)) {
		udp->len=htons(pack->alloc_len+data->alloc_len);
	}

	/* Find enclosing IP header and do the checksum */
	if(hdrs[strlen(hdrs)-1]=='i') {
		int i = strlen(hdrs)-1;
		if(!(headers[i]->modified&IP_MOD_PROTOCOL)) {
			((ip_header *)(headers[i]->data))->protocol=IPPROTO_UDP;
			headers[i]->modified |= IP_MOD_PROTOCOL;
		}
		if(!(pack->modified&UDP_MOD_CHECK)) {
			udpcsum(headers[i],pack,data);
		}
	} else if(hdrs[strlen(hdrs)-1]=='6') {
		int i = strlen(hdrs)-1;
		if(!(headers[i]->modified&IPV6_MOD_NXT)) {
			((ipv6_header *)(headers[i]->data))->ip6_nxt=IPPROTO_UDP;
			headers[i]->modified |= IPV6_MOD_NXT;
		}
		if(!(pack->modified&UDP_MOD_CHECK)) {
			udp6csum(headers[i],pack,data);
		}

	} else {
		if(!(pack->modified&UDP_MOD_CHECK)) {
			usage_error("UDP checksum not defined when UDP is not embedded in IP\n");
			return FALSE;
		}
	}

	return TRUE;
}

int num_opts() {
	return sizeof(udp_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return udp_opts;
}
char get_optchar() {
	return opt_char;
}
