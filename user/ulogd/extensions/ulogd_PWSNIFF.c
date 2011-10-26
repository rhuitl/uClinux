/* ulogd_PWSNIFF.c, Version $Revision: 686 $
 *
 * ulogd logging interpreter for POP3 / FTP like plaintext passwords.
 *
 * (C) 2000-2003 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: ulogd_PWSNIFF.c 686 2005-02-12 21:22:56Z laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "chtons.h"
#include <ulogd/ulogd.h>

#ifdef DEBUG_PWSNIFF
#define DEBUGP(x) ulogd_log(ULOGD_DEBUG, x)
#else
#define DEBUGP(format, args...)
#endif


#define PORT_POP3	110
#define PORT_FTP	21

static u_int16_t pwsniff_ports[] = {
	__constant_htons(PORT_POP3),
	__constant_htons(PORT_FTP),
	/* feel free to include any other ports here, provided that their
	 * user/password syntax is the same */
};

#define PWSNIFF_MAX_PORTS 2

static char *_get_next_blank(char* begp, char *endp)
{
	char *ptr;

	for (ptr = begp; ptr < endp; ptr++) {
		if (*ptr == ' ' || *ptr == '\n' || *ptr == '\r') {
			return ptr-1;	
		}
	}
	return NULL;
}

static ulog_iret_t *_interp_pwsniff(ulog_interpreter_t *ip, ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct tcphdr *tcph = protoh;
	u_int32_t tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	unsigned char  *ptr, *begp, *pw_begp, *endp, *pw_endp;
	ulog_iret_t *ret = ip->result;
	int len, pw_len, i, cont = 0;

	len = pw_len = 0;
	begp = pw_begp = NULL;

	if (iph->protocol != IPPROTO_TCP)
		return NULL;
	
	for (i = 0; i < PWSNIFF_MAX_PORTS; i++)
	{
		if (tcph->dest == pwsniff_ports[i]) {
			cont = 1; 
			break;
		}
	}
	if (!cont)
		return NULL;

	DEBUGP("----> pwsniff detected, tcplen=%d, struct=%d, iphtotlen=%d, ihl=%d\n", tcplen, sizeof(struct tcphdr), ntohs(iph->tot_len), iph->ihl);

	for (ptr = (unsigned char *) tcph + sizeof(struct tcphdr); 
			ptr < (unsigned char *) tcph + tcplen; ptr++)
	{
		if (!strncasecmp(ptr, "USER ", 5)) {
			begp = ptr+5;
			endp = _get_next_blank(begp, (char *)tcph + tcplen);
			if (endp)
				len = endp - begp + 1;
		}
		if (!strncasecmp(ptr, "PASS ", 5)) {
			pw_begp = ptr+5;
			pw_endp = _get_next_blank(pw_begp, 
					(char *)tcph + tcplen);
			if (pw_endp)
				pw_len = pw_endp - pw_begp + 1;
		}
	}

	if (len) {
		ret[0].value.ptr = (char *) malloc(len+1);
		ret[0].flags |= ULOGD_RETF_VALID;
		if (!ret[0].value.ptr) {
			ulogd_log(ULOGD_ERROR, "OOM (size=%u)\n", len);
			return NULL;
		}
		strncpy(ret[0].value.ptr, begp, len);
		*((char *)ret[0].value.ptr + len + 1) = '\0';
	}
	if (pw_len) {
		ret[1].value.ptr = (char *) malloc(pw_len+1);
		ret[1].flags |= ULOGD_RETF_VALID;
		if (!ret[1].value.ptr){
			ulogd_log(ULOGD_ERROR, "OOM (size=%u)\n", pw_len);
			return NULL;
		}
		strncpy(ret[1].value.ptr, pw_begp, pw_len);
		*((char *)ret[1].value.ptr + pw_len + 1) = '\0';

	}
	return ret;
}

static ulog_iret_t pwsniff_rets[] = {
	{ .type = ULOGD_RET_STRING, 
	  .flags = ULOGD_RETF_FREE, 
	  .key = "pwsniff.user", 
	}, 
	{ .type = ULOGD_RET_STRING, 
	  .flags = ULOGD_RETF_FREE, 
	  .key = "pwsniff.pass", 
	},
};

static ulog_interpreter_t base_ip[] = { 
	{ .name = "pwsniff", 
	  .interp = &_interp_pwsniff, 
	  .key_num = 2, 
	  .result = pwsniff_rets },
	{ NULL, "", 0, NULL, 0, NULL }, 
};

static void _base_reg_ip(void)
{
	ulog_interpreter_t *ip = base_ip;
	ulog_interpreter_t *p;

	for (p = ip; p->interp; p++)
		register_interpreter(p);
}


void _init(void)
{
	_base_reg_ip();
}
