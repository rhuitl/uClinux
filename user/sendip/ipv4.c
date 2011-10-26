/* ipv4.c - IPV4 code for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog from 2.0 release:
 * 26/11/2001 IP options
 * 23/01/2002 Spelling fix (Dax Kelson <dax@gurulabs.com>)
 * 26/08/2002 Put tot_len field in host byte order on FreeBSD
 * ChangeLog since 2.2 release:
 * 24/11/2002 make it compile on archs that care about alignment
 * ChangeLog since 2.3 release:
 * 23/12/2002 fix bug with -iossr and -iolsr
 * 20/01/2003 fix FreeBSD sendto(): invalid argument error.  Again.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "sendip_module.h"
#include "ipv4.h"

/* Character that identifies our options
 */
const char opt_char='i';

static void ipcsum(sendip_data *ip_hdr) {
	ip_header *ip = (ip_header *)ip_hdr->data;
	ip->check=0;
	ip->check=csum((u_int16_t *)ip_hdr->data, ip_hdr->alloc_len);
}

/* This builds a source route format option from an argument */
static u_int8_t buildroute(char *data) {
	char *data_out = data;
	char *data_in = data;
	char *next;
	u_int8_t p='0';
	int i;
	/* First, the first 2 bytes give us the pointer */
	for(i=0;i<2;i++) {
		p<<=4;
		if('0'<=*data_in && *data_in<='9') {
			p+=*data_in-'0';
		} else if('A'<=*data_in && *data_in<='F') {
			p+=*data_in-'A'+0x0A;
		} else if('a'<=*data_in && *data_in<='f') {
			p+=*data_in-'a'+0x0a;
		} else {
			fprintf(stderr,"First 2 chars of record route options must be hex pointer\n");
			return 0;
		}
		data_in++;
	}
	*(data_out++)=p;

	/* Now loop through IP addresses... */
	if(*data_in != ':') {
		fprintf(stderr,"Third char of a record route option must be a :\n");
		return 0;
	}
	data_in++;
	next=data_in;
	while(next) {
		u_int32_t ip;
		next=strchr(data_in,':');
		if(next) {
			*(next++)=0;
		}
		ip=inet_addr(data_in);
		memcpy(data_out,&ip,4);
		data_out+=4;
		data_in = next;
	}

	return (data_out-data);
}

/* This bears an incredible resemblance to the TCP addoption function... */
static void addoption(u_int8_t copy, u_int8_t class, u_int8_t num,
							 u_int8_t len, u_int8_t *data,
							 sendip_data *pack) {
	/* opt is copy flag (1bit) + class (2 bit) + number (5 bit) */
	u_int8_t opt = ((copy&1)<<7) | ((class&3)<<5) | (num&31);
	pack->data = realloc(pack->data, pack->alloc_len + len);
	*((u_int8_t *)pack->data+pack->alloc_len) = opt;
	if(len > 1)
		*((u_int8_t *)pack->data+pack->alloc_len+1) = len;
	if(len > 2)
		memcpy((u_int8_t *)pack->data+pack->alloc_len+2,data,len-2);
	pack->alloc_len += len;
}

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	ip_header *ip = malloc(sizeof(ip_header));
	memset(ip,0,sizeof(ip_header));
	ret->alloc_len = sizeof(ip_header);
	ret->data = (void *)ip;
	ret->modified=0;
	return ret;
}

bool set_addr(char *hostname, sendip_data *pack) {
	ip_header *ip = (ip_header *)pack->data;
	struct hostent *host = gethostbyname2(hostname,AF_INET);
	if(!(pack->modified & IP_MOD_SADDR)) {
		ip->saddr = inet_addr("127.0.0.1");
	} 
	if(!(pack->modified & IP_MOD_DADDR)) {
		if(host==NULL) return FALSE;
		if(host->h_length != sizeof(ip->daddr)) {
			fprintf(stderr,"IPV4 destination address is the wrong size!!!");
			return FALSE;
		}
		memcpy(&(ip->daddr),host->h_addr,host->h_length);
	}
	return TRUE;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	ip_header *iph = (ip_header *)pack->data;
	switch(opt[1]) {
	case 's':
		iph->saddr = inet_addr(arg);
		pack->modified |= IP_MOD_SADDR;
		break;
	case 'd':
		iph->daddr = inet_addr(arg);
		pack->modified |= IP_MOD_DADDR;
		break;
	case 'h':
		iph->header_len = (unsigned int)strtoul(arg, (char **)NULL, 0) & 0xF;
		pack->modified |= IP_MOD_HEADERLEN;
		break;
	case 'v':
		iph->version = (unsigned int)strtoul(arg, (char **)NULL, 0) & 0xF;
		pack->modified |= IP_MOD_VERSION;
		break;
	case 'y':
		iph->tos = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= IP_MOD_TOS;
		break;
	case 'l':
		iph->tot_len = (u_int16_t)strtoul(arg, (char **)NULL, 0);
#ifndef __FreeBSD__
#ifndef __FreeBSD
		iph->tot_len = htons(iph->tot_len);
#endif
#endif
		pack->modified |= IP_MOD_TOTLEN;
		break;
	case 'i':
		iph->id = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= IP_MOD_ID;
		break;

	case 'f':
		if(opt[2]) {
			/* Note: *arg&1 is what we want because:
				if arg=="0", *arg&1==0
				if arg=="1", *arg&1==1
				otherwise, it doesn't really matter...
			*/
			switch(opt[2]) {
			case 'r':
				iph->res=*arg&1;
				pack->modified |= IP_MOD_RES;
				break;
			case 'd':
				iph->df=*arg&1;
				pack->modified |= IP_MOD_DF;
				break;
			case 'm':
				iph->mf=*arg&1;
				pack->modified |= IP_MOD_MF;
				break;
			}
		} else {
			IP_SET_FRAGOFF(iph,(u_int16_t)strtoul(arg, (char **)NULL, 0) & 
				(u_int16_t)0x1FFF);
			pack->modified |= IP_MOD_FRAGOFF;
			break;
		}
		break;

	case 't':
		iph->ttl = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= IP_MOD_TTL;
		break;
	case 'p':
	   iph->protocol = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= IP_MOD_PROTOCOL;
		break;
	case 'c':
		iph->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= IP_MOD_CHECK;
		break;


	case 'o':
		/* IP options */
		if(!strcmp(opt+2, "num")) {
			/* Other options (auto legnth) */
			u_int8_t cp, cls, num, len;
			u_int8_t *data = malloc(strlen(arg)+2);
			if(!data) {
				fprintf(stderr,"Out of memory!\n");
				return FALSE;
			}
			sprintf(data,"0x%s",arg);
			len = compact_string(data);
			cp=(*data&0x80)>>7;
			cls=(*data&0x60)>>5;
			num=(*data&0x1F);
			addoption(cp,cls,num,len+1,data+1,pack);
			free(data);
		} else if(!strcmp(opt+2, "eol")) {
			/* End of list */
			addoption(0,0,0,1,NULL,pack);
		} else if(!strcmp(opt+2, "nop")) {
			/* NOP */
			addoption(0,0,1,1,NULL,pack);
		} else if(!strcmp(opt+2, "rr")) {
			/* Record route
			 * Format is the same as for loose source route
			 */
			char *data = strdup(arg);
			u_int8_t len;
			if(!data) {
				fprintf(stderr,"Out of memory!\n");
				return FALSE;
			}
			len = buildroute(data);
			if(len==0) {
				free(data);
				return FALSE;
			} else {
				addoption(0,0,7,len+2,data,pack);
				free(data);
			}
		} else if(!strcmp(opt+2, "ts")) {
			/* Time stamp (RFC791)
			 * Format is:
			 *  type (68, 8bit)
			 *  length (automatic, 8bit)
			 *  pointer (8bit)
			 *  overflow (4bit), flag (4bit)
			 *  if(flag) ip1 (32bit)
			 *  timestamp1 (32bit)
			 *  if(flag) ip2 (32bit)
			 *  timestamp2 (32bit)
			 *  ...
			 */
			char *data = strdup(arg);
			char *data_in = data;
			char *data_out = data;
			char *next;
			u_int8_t p=0;
			int i;
			if(data==NULL) {
				fprintf(stderr,"Out of memory\n");
				return FALSE;
			}

			/* First, get the pointer */
			for(i=0;i<2;i++) {
				p<<=4;
				if('0'<=*data_in && *data_in<='9') {
					p+=*data_in-'0';
				} else if('A'<=*data_in && *data_in<='F') {
					p+=*data_in-'A'+0x0A;
				} else if('a'<=*data_in && *data_in<='f') {
					p+=*data_in-'a'+0x0a;
				} else {
					fprintf(stderr,
							  "First 2 chars of IP timestamp must be hex pointer\n");
					free(data);
					return FALSE;
				}
				data_in++;
			}
			*(data_out++)=p;
			
			/* Skip a : */
			if(*(data_in++) != ':') {
				fprintf(stderr,"Third char of IP timestamp must be :\n");
				free(data);
				return FALSE;
			}

			/* Get the overflow and skip a : */
			next = strchr(data_in,':');
			if(!next) {
				fprintf(stderr,"IP timestamp option incorrect\n");
				free(data);
				return FALSE;
			}
			*(next++)=0;
			i = atoi(data_in);
			if(i > 15) {
				fprintf(stderr,"IP timestamp overflow too big (max 15)\n");
				free(data);
				return FALSE;
			}
			*data_out=(u_int8_t)(i<<4);
			data_in=next;
			
			/* Now get the flag and skip a : */
			next = strchr(data_in,':');
			if(!next) {
				fprintf(stderr,"IP timestamp option incorrect\n");
				free(data);
				return FALSE;
			}
			*(next++)=0;
			i = atoi(data_in);
			if(i > 15) {
				fprintf(stderr,"IP timestamp flag too big (max 3)\n");
				free(data);
				return FALSE;
			} else if(i!=0 && i!=1 && i!=3) {
				fprintf(stderr,
						  "Warning: IP timestamp flag value %d not understood\n",i);
			}
			(*data_out)+=(u_int8_t)i;
			data_in=next; data_out++;

			/* Fill in (ip?) timestamp pairs */
			while(next) {
				u_int32_t ts;
				if(i) { /* if we need IPs */
					u_int32_t ip;
					next=strchr(data_in,':');
					if(!next) {
						fprintf(stderr,"IP address in IP timestamp option must be followed by a timesamp\n");
						free(data);
						return FALSE;
					}
					*(next++)=0;
					ip=inet_addr(data_in);
					memcpy(data_out,&ip,4);
					data_out+=4;
					data_in = next;
				}
				next=strchr(next,':');
				if(next) *(next++)=0;
				ts = htonl(atoi(data_in));
				memcpy(data_out,&ts,4);
				data_out+=4;
				data_in = next;
			}

			addoption(0,2,4,data_out-data+2,data,pack);
			free(data);
			/* End of timestamp parsing */

		} else if(!strcmp(opt+2, "lsr")) {
			/* Loose Source Route 
			 * Format is:
			 *  type (131, 8bit)
			 *  length (automatic, 8bit)
			 *  pointer (>=4, 8bit)
			 *  ip address0 (32bit)
			 *  ip address1 (32bit) 
			 *  ...
			 */
			char *data = strdup(arg);
			u_int8_t len;
			if(!data) {
				fprintf(stderr,"Out of memory!\n");
				return FALSE;
			}
			len = buildroute(data);
			if(len==0) {
				free(data);
				return FALSE;
			} else {
				addoption(1,0,3,len+2,data,pack);
				free(data);
			}
		} else if(!strcmp(opt+2, "sid")) {
			/* Stream ID (RFC791) */
			u_int16_t sid = htons(atoi(arg));
			addoption(1,0,8,4,(u_int8_t *)&sid,pack);
		} else if(!strcmp(opt+2, "ssr")) {
			/* Strict Source Route 
			 * Format is identical to loose source route
			 */
			char *data = strdup(arg);
			u_int8_t len;
			if(!data) {
				fprintf(stderr,"Out of memory!\n");
				return FALSE;
			}
			len = buildroute(data);
			if(len==0) {
				free(data);
				return FALSE;
			} else {
				addoption(1,0,9,len+2,data,pack);
				free(data);
			}
		} else {
			fprintf(stderr, "unsupported IP option %s val %s\n", opt, arg);
			return FALSE;
		}
		break;

	default:
		usage_error("unknown IP option\n");
		return FALSE;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	ip_header *iph = (ip_header *)pack->data;

	if(!(pack->modified & IP_MOD_VERSION)) {
		iph->version=4;
	}
	if(!(pack->modified & IP_MOD_HEADERLEN)) {
		iph->header_len=(pack->alloc_len+3)/4;
	}
	if(!(pack->modified & IP_MOD_TOTLEN)) {
		iph->tot_len=pack->alloc_len + data->alloc_len;
#ifndef __FreeBSD__
#ifndef __FreeBSD
		iph->tot_len = htons(iph->tot_len);
#endif
#endif
	}
	if(!(pack->modified & IP_MOD_ID)) {
		iph->id = rand();
	}
	if(!(pack->modified & IP_MOD_TTL)) {
		iph->ttl = 255;
	}
	if(!(pack->modified & IP_MOD_CHECK)) {
		ipcsum(pack);
	}
	return TRUE;
}

int num_opts() {
	return sizeof(ip_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return ip_opts;
}
char get_optchar() {
	return opt_char;
}
