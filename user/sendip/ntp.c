/* ntp.c - Network Timxe Protocol module for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.1 release:
 */

#include <stdlib.h>
#include <sys/types.h>
#include <math.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "sendip_module.h"
#include "ntp.h"

/* Character that identifies our options
 */
const char opt_char='n';

u_int32_t make_fixed_point(double n, bool issigned, int totbits, int intbits) {
	u_int32_t intpart;
	u_int32_t fracpart;
	u_int32_t result;
	bool signbit;
	double intpartd, fracpartd;
	int fracbits;

	if(issigned) totbits--;

	fracbits=totbits-intbits;

	if(issigned && n<0) {
		signbit=TRUE;
	} else {
		signbit=FALSE;
	} /* else, signbit is unused */

	n=fabs(n);

/*
	fracpartd=floor(ldexp(modf(n,&intpartd),ldexp(2.0,fracbits)));
*/
	fracpartd=floor(ldexp(modf(n,&intpartd),32));
	intpart=(u_int32_t)intpartd;
	fracpart=(u_int32_t)fracpartd;
 
	
	if(issigned&&signbit) {
		result=1<<totbits;
	} else {
		result=0;
	}

	if(intbits!=0) {
		intpart&=(1<<intbits)-1;
		intpart<<=(totbits-intbits);
		result|=intpart;
	}
	if(intbits!=totbits) {
		if(fracbits!=32) {
			fracpart&=((1<<fracbits)-1)<<intbits;
			fracpart>>=intbits;
		}
		result|=fracpart;
	}
	return htonl(result);
}

bool make_ts(ntp_ts *dest, char *src) {
	char *intpart, *fracpart;
	intpart=src;
	fracpart=strchr(intpart,'.');

	if(*intpart) {
		dest->intpart=(u_int32_t)strtoul(intpart,&fracpart,0);
	} else {
		dest->intpart=0;
	}
	fracpart++;  // skip the .
	if(fracpart && *fracpart) {
		double d;
		d = strtod(fracpart-1,(char **)NULL);
		dest->fracpart=make_fixed_point(d,FALSE,32,0);
	}
	return TRUE;
}

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	ntp_header *ntp = malloc(sizeof(ntp_header));
	memset(ntp,0,sizeof(ntp_header));
	ret->alloc_len = sizeof(ntp_header);
	ret->data = (void *)ntp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	ntp_header *ntp = (ntp_header *)pack->data;
	switch(opt[1]) {
	case 'l':  /* Leap Indicator (2 bits) */
		ntp->leap=(u_int8_t)strtoul(arg,(char **)NULL,0)&3;
		pack->modified|=NTP_MOD_LEAP;
		break;
	case 's':  /* Status (6 bits, values 0-4 defined */
		ntp->status=(u_int8_t)strtoul(arg,(char **)NULL,0)&0x3F;
		pack->modified|=NTP_MOD_STATUS;
		break;
	case 't':  /* Type (8 bits, values 0-4 defined */
		ntp->type=(u_int8_t)strtoul(arg,(char **)NULL,0)&0xFF;
		pack->modified|=NTP_MOD_TYPE;
		break;
	case 'p':  /* precision (16 bits, range +32 to -32) */
		ntp->precision=htons((int8_t)strtol(arg,(char **)NULL,0));
		pack->modified|=NTP_MOD_PRECISION;
		break;
	case 'e':  /* esitmated error (32 bits, fixed point between bits 15/16) */
		ntp->error=make_fixed_point(strtod(arg,(char **)NULL),FALSE,32,16);
		pack->modified|=NTP_MOD_ERROR;
		break;
	case 'd':  /* estimated drift rate (32 bits, signed fixed point left of
					  high order bit) */
		ntp->drift=make_fixed_point(strtod(arg,(char **)NULL),TRUE,32,0);
		pack->modified|=NTP_MOD_DRIFT;
		break;
	case 'r':  /* reference clock id (32 bits or a 4 byte string).  Can be:
					  If type==1: "WWVB", "GOES", "WWV\0"
					  If type==2: IP address
					  Else: must be zero
				  */
		if('0'<=*arg&&*arg<='9') {
			/* either a number or an IP */
			if((ntp->reference.ipaddr=inet_addr(arg))==-1) {
				/* Not a valid IP, or really want 255.255.255.255 */
				if(strcmp(arg,"255.255.255.255")) {
					ntp->reference.ipaddr=htonl(strtol(arg,(char **)NULL,0));
				}
			}
		} else {
			/* Hopefully a 4 byte or less string */
			ntp->reference.ipaddr = 0;
			if(strlen(arg)<=4) {
				memcpy(ntp->reference.id,arg,strlen(arg));
			} else {
				usage_error("NTP reference clock ID must be IP addr, 32 bit integer, or 4 byte string\n");
				return FALSE;
			}
		}
		pack->modified|=NTP_MOD_REF;
		break;
	case 'f':  /* reference timestamp (64 bits) */
		if(make_ts(&(ntp->reference_ts),arg)) {
			pack->modified|=NTP_MOD_REFERENCE;
		} else {
			usage_error("Couldn't parse NTP reference timestamp\n");
			return FALSE;
		}
		break;
	case 'o':  /* originate timestamp (64 bits) */
		if(make_ts(&(ntp->originate_ts),arg)) {
			pack->modified|=NTP_MOD_ORIGINATE;
		} else {
			usage_error("Couldn't parse NTP originate timestamp\n");
			return FALSE;
		}
		break;
	case 'a':  /* receive timestamp (64 bits) */
		if(make_ts(&(ntp->receive_ts),arg)) {
			pack->modified|=NTP_MOD_RECEIVE;
		} else {
			usage_error("Couldn't parse NTP receive timestamp\n");
			return FALSE;
		}
		break;
	case 'x':  /* transmit timestamp (64 bits) */
		if(make_ts(&(ntp->transmit_ts),arg)) {
			pack->modified|=NTP_MOD_TRANSMIT;
		} else {
			usage_error("Couldn't parse NTP transmit timestamp\n");
			return FALSE;
		}
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	if(hdrs[strlen(hdrs)-1] != 'u') {
		usage_error("Warning: NTP should be contained in a UDP packet\n");
	}
	return TRUE;
}

int num_opts() {
	return sizeof(ntp_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return ntp_opts;
}
char get_optchar() {
	return opt_char;
}
