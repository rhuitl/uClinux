/* ulogd_PWSNIFF.c, Version $Revision$
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
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ulogd/ulogd.h>

#ifdef DEBUG_PWSNIFF
#define DEBUGP(x) ulogd_log(ULOGD_DEBUG, x)
#else
#define DEBUGP(format, args...)
#endif


#define PORT_POP3	110
#define PORT_FTP	21

static u_int16_t pwsniff_ports[] = {
	PORT_POP3,
	PORT_FTP,
	/* feel free to include any other ports here, provided that their
	 * user/password syntax is the same */
};

static unsigned char *_get_next_blank(unsigned char* begp, unsigned char *endp)
{
	unsigned char *ptr;

	for (ptr = begp; ptr < endp; ptr++) {
		if (*ptr == ' ' || *ptr == '\n' || *ptr == '\r')
			return ptr-1;	
	}
	return NULL;
}

static int interp_pwsniff(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *inp = pi->input.keys;
	struct ulogd_key *ret = pi->output.keys;
	struct iphdr *iph;
	void *protoh;
	struct tcphdr *tcph;	
	unsigned int tcplen;
	unsigned char  *ptr, *begp, *pw_begp, *endp, *pw_endp;
	int len, pw_len, i, cont = 0;

	if (!IS_VALID(pi->input.keys[0]))
		return 0;
	
	iph = (struct iphdr *) pi->input.keys[0].u.value.ptr;
	protoh = (u_int32_t *)iph + iph->ihl;
	tcph = protoh;
	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

	len = pw_len = 0;
	begp = pw_begp = NULL;

	if (iph->protocol != IPPROTO_TCP)
		return 0;
	
	for (i = 0; i < ARRAY_SIZE(pwsniff_ports); i++)
	{
		if (ntohs(tcph->dest) == pwsniff_ports[i]) {
			cont = 1; 
			break;
		}
	}
	if (!cont)
		return 0;

	DEBUGP("----> pwsniff detected, tcplen=%d, struct=%d, iphtotlen=%d, "
		"ihl=%d\n", tcplen, sizeof(struct tcphdr), ntohs(iph->tot_len),
		iph->ihl);

	for (ptr = (unsigned char *) tcph + sizeof(struct tcphdr); 
			ptr < (unsigned char *) tcph + tcplen; ptr++)
	{
		if (!strncasecmp((char *)ptr, "USER ", 5)) {
			begp = ptr+5;
			endp = _get_next_blank(begp, (unsigned char *)tcph + tcplen);
			if (endp)
				len = endp - begp + 1;
		}
		if (!strncasecmp((char *)ptr, "PASS ", 5)) {
			pw_begp = ptr+5;
			pw_endp = _get_next_blank(pw_begp, 
					(unsigned char *)tcph + tcplen);
			if (pw_endp)
				pw_len = pw_endp - pw_begp + 1;
		}
	}

	if (len) {
		ret[0].u.value.ptr = (char *) malloc(len+1);
		ret[0].flags |= ULOGD_RETF_VALID;
		if (!ret[0].u.value.ptr) {
			ulogd_log(ULOGD_ERROR, "OOM (size=%u)\n", len);
			return 0;
		}
		strncpy((char *) ret[0].u.value.ptr, (char *)begp, len);
		*((char *)ret[0].u.value.ptr + len + 1) = '\0';
	}
	if (pw_len) {
		ret[1].u.value.ptr = (char *) malloc(pw_len+1);
		ret[1].flags |= ULOGD_RETF_VALID;
		if (!ret[1].u.value.ptr){
			ulogd_log(ULOGD_ERROR, "OOM (size=%u)\n", pw_len);
			return 0;
		}
		strncpy((char *)ret[1].u.value.ptr, (char *)pw_begp, pw_len);
		*((char *)ret[1].u.value.ptr + pw_len + 1) = '\0';

	}
	return 0;
}

static struct ulogd_key pwsniff_inp[] = {
	{
		.name 	= "raw.pkt",
	},
};

static struct ulogd_key pwsniff_outp[] = {
	{
		.name	= "pwsniff.user",
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_RETF_FREE,
	},
	{
		.name 	= "pwsniff.pass",
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_RETF_FREE,
	},
};

static struct ulogd_plugin pwsniff_plugin = {
	.name	= "PWSNIFF",
	.input	= {
		.keys = pwsniff_inp,
		.num_keys = ARRAY_SIZE(pwsniff_inp),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output	= {
		.keys = pwsniff_outp,
		.num_keys = ARRAY_SIZE(pwsniff_outp),
		.type = ULOGD_DTYPE_PACKET,
	},
	.interp = &interp_pwsniff,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void)
{
	ulogd_register_plugin(&pwsniff_plugin);
}
