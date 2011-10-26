/* tcp.c - tcp support for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * TCP options taken from code by Alexander Talos <at@atat.at>
 * ChangeLog since 2.0 release:
 * 27/11/2001: Added -tonum option
 * 02/12/2001: Only check 1 layer for enclosing IPV4 header
 * ChangeLog since 2.1 release:
 * 16/04/2002: Tidy up checksum code (like in icmp.c)
 * 16/04/2002: Add support for TCP over IPV6 (code from armite <armite@163.com>)
 * 26/08/2002: Fix bug where tcp length was wrong with tcp options
 * ChangeLog since 2.2 release:
 * 24/11/2002: made it compile on archs that care about alignment
 * ChangeLog since 2.4 release:
 * 21/04/2003: fix errors found by valgrind
 * 10/06/2003: fix -tonum (pointed out by Yaniv Kaul <ykaul@checkpoint.com>)
 */

#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "sendip_module.h"
#include "tcp.h"
#include "ipv4.h"
#include "ipv6.h"

/* Character that identifies our options
 */
const char opt_char='t';

static void tcpcsum(sendip_data *ip_hdr, sendip_data *tcp_hdr,
						  sendip_data *data) {
	tcp_header *tcp = (tcp_header *)tcp_hdr->data;
	ip_header  *ip  = (ip_header *)ip_hdr->data;
	u_int16_t *buf = malloc(12+tcp_hdr->alloc_len+data->alloc_len);
	u_int8_t *tempbuf = (u_int8_t *)buf;
	tcp->check=0;
	if(tempbuf == NULL) {
		fprintf(stderr,"Out of memory: TCP checksum not computed\n");
		return;
	}
	/* Set up the pseudo header */
	memcpy(tempbuf,&(ip->saddr),sizeof(u_int32_t));
	memcpy(&(tempbuf[4]),&(ip->daddr),sizeof(u_int32_t));
	tempbuf[8]=0;
	tempbuf[9]=(u_int16_t)ip->protocol;
	tempbuf[10]=(u_int16_t)((tcp_hdr->alloc_len+data->alloc_len)&0xFF00)>>8;
	tempbuf[11]=(u_int16_t)((tcp_hdr->alloc_len+data->alloc_len)&0x00FF);
	/* Copy the TCP header and data */
	memcpy(tempbuf+12,tcp_hdr->data,tcp_hdr->alloc_len);
	memcpy(tempbuf+12+tcp_hdr->alloc_len,data->data,data->alloc_len);
	/* CheckSum it */
	tcp->check = csum(buf,12+tcp_hdr->alloc_len+data->alloc_len);
	free(buf);
}

static void tcp6csum(sendip_data *ipv6_hdr, sendip_data *tcp_hdr,
							sendip_data *data) {
	tcp_header *tcp = (tcp_header *)tcp_hdr->data;
	ipv6_header  *ipv6  = (ipv6_header *)ipv6_hdr->data;
	struct ipv6_pseudo_hdr phdr;

	u_int16_t *buf = malloc(sizeof(phdr)+tcp_hdr->alloc_len+data->alloc_len);
	u_int8_t *tempbuf = (u_int8_t *)buf;
	tcp->check=0;
	if(tempbuf == NULL) {
		fprintf(stderr,"Out of memory: TCP checksum not computed\n");
		return;
	}

	/* Set up the pseudo header */
	memset(&phdr,0,sizeof(phdr));
	memcpy(&phdr.source,&ipv6->ip6_src,sizeof(struct in6_addr));
	memcpy(&phdr.destination,&ipv6->ip6_dst,sizeof(struct in6_addr));
	phdr.ulp_length=IPPROTO_TCP;
	
	memcpy(tempbuf,&phdr,sizeof(phdr));

	/* Copy the TCP header and data */
	memcpy(tempbuf+sizeof(phdr),tcp_hdr->data,tcp_hdr->alloc_len);
	memcpy(tempbuf+sizeof(phdr)+tcp_hdr->alloc_len,data->data,data->alloc_len);

	/* CheckSum it */
	tcp->check = csum(buf,sizeof(phdr)+tcp_hdr->alloc_len+data->alloc_len);
	free(buf);
}

static void addoption(u_int8_t opt, u_int8_t len, u_int8_t *data,
							 sendip_data *pack) {
	pack->data = realloc(pack->data, pack->alloc_len + len);
	*((u_int8_t *)pack->data+pack->alloc_len) = opt;
	if(len > 1)
		*((u_int8_t *)pack->data+pack->alloc_len+1)=len;
	if(len > 2)
		memcpy((u_int8_t *)pack->data+pack->alloc_len+2,data,len-2);
	pack->alloc_len += len;
}

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	tcp_header *tcp = malloc(sizeof(tcp_header));
	memset(tcp,0,sizeof(tcp_header));
	ret->alloc_len = sizeof(tcp_header);
	ret->data = (void *)tcp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	tcp_header *tcp = (tcp_header *)pack->data;
	// opt[0]==t
	switch(opt[1]) {
	case 's':
		tcp->source = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= TCP_MOD_SOURCE;
		break;
	case 'd':
		tcp->dest = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= TCP_MOD_DEST;
		break;
	case 'n':
		tcp->seq = htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= TCP_MOD_SEQ;
		break;
	case 'a':
		tcp->ack_seq = htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= TCP_MOD_ACKSEQ;
		if(!(pack->modified&TCP_MOD_ACK)) {
			tcp->ack = 1;
			pack->modified |= TCP_MOD_ACK;
		}
		break;
	case 't':
		tcp->off = (u_int16_t)strtoul(arg, (char **)NULL, 0) &0xF;
		pack->modified |= TCP_MOD_OFF;
		break;
	case 'r':
		tcp->res = (u_int16_t)(strtoul(arg, (char **)NULL, 0) & 0x000F);
		pack->modified |= TCP_MOD_RES;
		break;
	case 'f':
		switch(opt[2]) {
		case 'e':
			tcp->ecn=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_ECN;
			break;
		case 'c':
			tcp->cwr=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_CWR;
			break;
		case 'u':
			tcp->urg=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_URG;
			break;
		case 'a':
			tcp->ack=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_ACK;
			break;
		case 'p':
			tcp->psh=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_PSH;
			break;
		case 'r':
			tcp->rst=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_RST;
			break;
		case 's':
			tcp->syn=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_SYN;
			break;
		case 'f':
			tcp->fin=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_FIN;
			break;
		default:
			usage_error("TCP flag not known\n");
			return FALSE;
		}
		break;
	case 'w':
		tcp->window = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= TCP_MOD_WINDOW;
		break;
	case 'c':
		tcp->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= TCP_MOD_CHECK;
		break;
	case 'u':
		tcp->urg_ptr = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= TCP_MOD_URGPTR;
		if(!(pack->modified&TCP_MOD_URG)) {
			tcp->urg = 1;
			pack->modified |= TCP_MOD_URG;
		}
		break;

	case 'o':
		/* TCP OPTIONS */
		if(!strcmp(opt+2, "num")) {
			/* Other options (auto length) */
			u_int8_t *data = malloc(strlen(arg)+2);
			int len;
			if(!data) {
				fprintf(stderr,"Out of memory!\n");
				return FALSE;
			}
			sprintf(data,"0x%s",arg);
			len = compact_string(data);
			if(len==1)
				addoption(*data,1,NULL,pack);
			else
				addoption(*data,len+1,data+1,pack);
			free(data);
		} else if (!strcmp(opt+2, "eol")) {
			/* End of options list RFC 793 kind 0, no length */
			addoption(0,1,NULL,pack);
		} else if (!strcmp(opt+2, "nop")) {
			/* No op RFC 793 kind 1, no length */
			addoption(1,1,NULL,pack);
		} else if (!strcmp(opt+2, "mss")) {
			/* Maximum segment size RFC 793 kind 2 */
			u_int16_t mss=htons(atoi(arg));
			addoption(2,4,(u_int8_t *)&mss,pack);
		} else if (!strcmp(opt+2, "wscale")) {
			/* Window scale rfc1323 */
			u_int8_t wscale=atoi(arg);
			addoption(3,3,&wscale,pack);
		} else if (!strcmp(opt+2, "sackok")) {
			/* Selective Acknowledge permitted rfc1323 */
			addoption(4,2,NULL,pack);
		} else if (!strcmp(opt+2, "sack")) {
		   /* Selective Acknowledge rfc1323 */
			unsigned char *next;
			u_int32_t le, re;
			u_int8_t *comb, *c;
			int count=0;

			/* count the options */
			next=arg;
			while(next) {
				next=strchr(next,',');
				count++;
				if(next) next++;
			}
			
			comb = malloc(count*8);
			c = comb;
			
			next=arg;
			while(*next) { 
				/* get left edge */
				next=strchr(arg, ':');
				if (!next) { 
					fprintf(stderr, 
							  "Value in tcp sack option incorrect. Usage: \n");
					fprintf(stderr, 
							  " -tosack left:right[,left:right...]\n");
					return FALSE;
				}
				*next++=0;
				le=atoi(arg);
				arg=next;
				/* get right edge */
				next=strchr(arg, ',');
				if (!next) 
					next=arg-1; /* Finito - next points to \0 */ 
				else
					*next++=0;
				re=atoi(arg);
				arg=next;
				
				le=htonl(le);
				re=htonl(re);
				memcpy(c, &le, 4);
				memcpy(c+4, &re, 4);
				c+=8;
			}
			addoption(5,count*8+2,comb,pack);
			free(comb);
		} else if (!strcmp(opt+2, "ts")) {
			/* Timestamp rfc1323 */
			u_int32_t tsval=0, tsecr=0;
			u_int8_t comb[8];
			if (2!=sscanf(arg, "%d:%d", &tsval, &tsecr)) {
				fprintf(stderr, 
						  "Invalid value for tcp timestamp option.\n");
				fprintf(stderr, 
						  "Usage: -tots tsval:tsecr\n");
				return FALSE;
			}
			tsval=htonl(tsval);
			memcpy(comb, &tsval, 4);
			tsecr=htonl(tsecr);
			memcpy(comb+4, &tsecr, 4);
			addoption(8,10,comb,pack);
		} else {
			/* Unrecognized -to* */
			fprintf(stderr, "unsupported TCP Option %s val %s\n", 
					  opt, arg);
			return FALSE;
		} 
		break;
		
	default:
		usage_error("unknown TCP option\n");
		return FALSE;
		break;

	}

	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	tcp_header *tcp = (tcp_header *)pack->data;
	
	/* Set relevant fields */
	if(!(pack->modified&TCP_MOD_SEQ)) {
		tcp->seq = (u_int32_t)rand();
	}
	if(!(pack->modified&TCP_MOD_OFF)) {
		tcp->off = (u_int16_t)((pack->alloc_len+3)/4) & 0x0F;
	}
	if(!(pack->modified&TCP_MOD_SYN)) {
		tcp->syn=1;
	}
	if(!(pack->modified&TCP_MOD_WINDOW)) {
		tcp->window=htons((u_int16_t)65535);
	}

	/* Find enclosing IP header and do the checksum */
	if(hdrs[strlen(hdrs)-1]=='i') {
		int i = strlen(hdrs)-1;
		if(!(headers[i]->modified&IP_MOD_PROTOCOL)) {
			((ip_header *)(headers[i]->data))->protocol=IPPROTO_TCP;
			headers[i]->modified |= IP_MOD_PROTOCOL;
		}
		if(!(pack->modified&TCP_MOD_CHECK)) {
			tcpcsum(headers[i],pack,data);
		}
	} else if(hdrs[strlen(hdrs)-1]=='6') {
		int i = strlen(hdrs)-1;
		if(!(headers[i]->modified&IPV6_MOD_NXT)) {
			((ipv6_header *)(headers[i]->data))->ip6_nxt=IPPROTO_TCP;
			headers[i]->modified |= IPV6_MOD_NXT;
		}
		if(!(pack->modified&TCP_MOD_CHECK)) {
			tcp6csum(headers[i],pack,data);
		}
	} else {
		if(!(pack->modified&TCP_MOD_CHECK)) {
			usage_error("TCP checksum not defined when TCP is not embedded in IP\n");
			return FALSE;
		}
	}
	
	return TRUE;
}

int num_opts() {
	return sizeof(tcp_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return tcp_opts;
}
char get_optchar() {
	return opt_char;
}
