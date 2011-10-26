/* ulogd_MAC.c, Version $Revision: 686 $
 *
 * ulogd interpreter plugin for 
 * 	o MAC addresses
 * 	o NFMARK field
 * 	o TIME
 * 	o Interface names
 * 	o IP header
 * 	o TCP header
 * 	o UDP header
 * 	o ICMP header
 * 	o AH/ESP header
 *
 * (C) 2000-2001 by Harald Welte <laforge@gnumonks.org>
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
 
 * $Id: ulogd_BASE.c 686 2005-02-12 21:22:56Z laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <ulogd/ulogd.h>

/***********************************************************************
 * 			Raw header
 ***********************************************************************/
static ulog_iret_t raw_rets[] = {
	{ .type = ULOGD_RET_STRING, 
	  .flags = ULOGD_RETF_FREE, 
	  .key = "raw.mac",
	},
	{ .type = ULOGD_RET_RAW,
	  .flags = ULOGD_RETF_NONE,
	  .key = "raw.pkt",
	},
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "raw.pktlen",
	},
};

static ulog_iret_t *_interp_raw(ulog_interpreter_t *ip, 
				ulog_packet_msg_t *pkt)
{
	unsigned char *p;
	int i;
	char *buf, *oldbuf = NULL;
	ulog_iret_t *ret = ip->result;

	if (pkt->mac_len) {
		buf = (char *) malloc(3 * pkt->mac_len + 1);
		if (!buf) {
			ulogd_log(ULOGD_ERROR, "OOM!!!\n");
			return NULL;
		}
		*buf = '\0';

		p = pkt->mac;
		oldbuf = buf;
		for (i = 0; i < pkt->mac_len; i++, p++)
			sprintf(buf, "%s%02x%c", oldbuf, *p, i==pkt->mac_len-1 ? ' ':':');
		ret[0].value.ptr = buf;
		ret[0].flags |= ULOGD_RETF_VALID;
	}

	/* include pointer to raw ipv4 packet */
	ret[1].value.ptr = pkt->payload;
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui32 = pkt->data_len;
	ret[2].flags |= ULOGD_RETF_VALID;

	return ret;
}

/***********************************************************************
 * 			OUT OF BAND
 ***********************************************************************/

static ulog_iret_t oob_rets[] = {
	{ .type = ULOGD_RET_STRING, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "oob.prefix",
	},
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "oob.time.sec", 
	},
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "oob.time.usec", 
	},
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "oob.mark", 
	},
	{ .type = ULOGD_RET_STRING, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "oob.in", 
	}, 
	{ .type = ULOGD_RET_STRING, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "oob.out", 
	},
};

static ulog_iret_t *_interp_oob(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret = ip->result;

	ret[0].value.ptr = pkt->prefix;
	ret[0].flags |= ULOGD_RETF_VALID;

	/* god knows why timestamp_usec contains crap if timestamp_sec == 0
	 * if (pkt->timestamp_sec || pkt->timestamp_usec) { */
	if (pkt->timestamp_sec) {
		ret[1].value.ui32 = pkt->timestamp_sec;
		ret[1].flags |= ULOGD_RETF_VALID;
		ret[2].value.ui32 = pkt->timestamp_usec;
		ret[2].flags |= ULOGD_RETF_VALID;
	} else {
		ret[1].flags &= ~ULOGD_RETF_VALID;
		ret[2].flags &= ~ULOGD_RETF_VALID;
	}

	ret[3].value.ui32 = pkt->mark;
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].value.ptr = pkt->indev_name;
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].value.ptr = pkt->outdev_name;
	ret[5].flags |= ULOGD_RETF_VALID;
	
	return ret;
}

/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static ulog_iret_t iphdr_rets[] = {
	{ .type = ULOGD_RET_IPADDR, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.saddr", 
	},
	{ .type = ULOGD_RET_IPADDR, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.daddr", 
	},
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.protocol", 
	},
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.tos", 
	},
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.ttl", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.totlen", 
	},
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.ihl", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.csum", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.id", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ip.fragoff", 
	},
};

static ulog_iret_t *_interp_iphdr(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret = ip->result;
	struct iphdr *iph = (struct iphdr *) pkt->payload;

	ret[0].value.ui32 = ntohl(iph->saddr);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui32 = ntohl(iph->daddr);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui8 = iph->protocol;
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].value.ui8 = iph->tos;
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].value.ui8 = iph->ttl;
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].value.ui16 = ntohs(iph->tot_len);
	ret[5].flags |= ULOGD_RETF_VALID;
	ret[6].value.ui8 = iph->ihl;
	ret[6].flags |= ULOGD_RETF_VALID;
	ret[7].value.ui16 = ntohs(iph->check);
	ret[7].flags |= ULOGD_RETF_VALID;
	ret[8].value.ui16 = ntohs(iph->id);
	ret[8].flags |= ULOGD_RETF_VALID;
	ret[9].value.ui16 = ntohs(iph->frag_off);
	ret[9].flags |= ULOGD_RETF_VALID;

	return ret;
}

/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/
static ulog_iret_t tcphdr_rets[] = {
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.sport", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.dport", 
	},
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.seq",
	},
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.ackseq", 
	}, 
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.offset",
	}, 
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.reserved",
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.window",
	},
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.urg", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.urgp",
	}, 
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.ack", 
	},
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE,
	  .key = "tcp.psh", 
	},
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.rst", 
	},
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.syn", 
	}, 
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.fin", 
	},
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.res1",
	},
	{ .type = ULOGD_RET_BOOL, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.res2",
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "tcp.csum",
	},
};

static ulog_iret_t *_interp_tcphdr(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct tcphdr *tcph = (struct tcphdr *) protoh;
	ulog_iret_t *ret = ip->result;

	if (iph->protocol != IPPROTO_TCP)
		return NULL;
	
	ret[0].value.ui16 = ntohs(tcph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui16 = ntohs(tcph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui32 = ntohl(tcph->seq);
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].value.ui32 = ntohl(tcph->ack_seq);
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].value.ui8 = ntohs(tcph->doff);
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].value.ui8 = ntohs(tcph->res1);
	ret[5].flags |= ULOGD_RETF_VALID;
	ret[6].value.ui16 = ntohs(tcph->window);
	ret[6].flags |= ULOGD_RETF_VALID;

	ret[7].value.b = tcph->urg;
	ret[7].flags |= ULOGD_RETF_VALID;
	if (tcph->urg) {
		ret[8].value.ui16 = ntohs(tcph->urg_ptr);
		ret[8].flags |= ULOGD_RETF_VALID;
	}
	ret[9].value.b = tcph->ack;
	ret[9].flags |= ULOGD_RETF_VALID;
	ret[10].value.b = tcph->psh;
	ret[10].flags |= ULOGD_RETF_VALID;
	ret[11].value.b = tcph->rst;
	ret[11].flags |= ULOGD_RETF_VALID;
	ret[12].value.b = tcph->syn;
	ret[12].flags |= ULOGD_RETF_VALID;
	ret[13].value.b = tcph->fin;
	ret[13].flags |= ULOGD_RETF_VALID;
	ret[14].value.b = tcph->res1;
	ret[14].flags |= ULOGD_RETF_VALID;
	ret[15].value.b = tcph->res2;
	ret[15].flags |= ULOGD_RETF_VALID;
	ret[16].value.ui16 = ntohs(tcph->check);
	ret[16].value.ui16 = ULOGD_RETF_VALID;
	
	return ret;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/
static ulog_iret_t udphdr_rets[] = {
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "udp.sport", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "udp.dport", 
	}, 
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "udp.len", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "udp.csum",
	},
};

static ulog_iret_t *_interp_udp(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct udphdr *udph = protoh;
	ulog_iret_t *ret = ip->result;

	if (iph->protocol != IPPROTO_UDP)
		return NULL;

	ret[0].value.ui16 = ntohs(udph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui16 = ntohs(udph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui16 = ntohs(udph->len);
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].value.ui16 = ntohs(udph->check);
	ret[3].flags |= ULOGD_RETF_VALID;
	
	return ret;
}

/***********************************************************************
 * 			ICMP HEADER
 ***********************************************************************/

static ulog_iret_t icmphdr_rets[] = {
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "icmp.type", 
	}, 
	{ .type = ULOGD_RET_UINT8, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "icmp.code", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "icmp.echoid", 
	}, 
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "icmp.echoseq", 
	},
	{ .type = ULOGD_RET_IPADDR, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "icmp.gateway", 
	},
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "icmp.fragmtu", 
	}, 
	{ .type = ULOGD_RET_UINT16, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "icmp.csum",
	},
};

static ulog_iret_t *_interp_icmp(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct icmphdr *icmph = protoh;
	ulog_iret_t *ret = ip->result;

	if (iph->protocol != IPPROTO_ICMP)
		return NULL;
	
	ret[0].value.ui8 = icmph->type;
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui8 = icmph->code;
	ret[1].flags |= ULOGD_RETF_VALID;

	switch(icmph->type) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			ret[2].value.ui16 = ntohs(icmph->un.echo.id);
			ret[2].flags |= ULOGD_RETF_VALID;
			ret[3].value.ui16 = ntohs(icmph->un.echo.sequence);
			ret[3].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_REDIRECT:
		case ICMP_PARAMETERPROB:
			ret[4].value.ui32 = ntohl(icmph->un.gateway);
			ret[4].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_DEST_UNREACH:
			if (icmph->code == ICMP_FRAG_NEEDED) {
				ret[5].value.ui16 = ntohs(icmph->un.frag.mtu);
				ret[5].flags |= ULOGD_RETF_VALID;
			}
			break;
	}
	ret[6].value.ui16 = icmph->checksum;
	ret[6].flags |= ULOGD_RETF_VALID;

	return ret;
}

/***********************************************************************
 * 			IPSEC HEADER 
 ***********************************************************************/

static ulog_iret_t ahesphdr_rets[] = {
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "ahesp.spi", 
	},
};

static ulog_iret_t *_interp_ahesp(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{

	ulog_iret_t *ret = ip->result;
#if 0
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *) (iph + iph->ihl);
	struct esphdr *esph = protoh;

	if (iph->protocol != IPPROTO_ESP)
		return NULL;

	ret[0].value.ui32 = ntohl(esph->spi);
	ret[0].flags |= ULOGD_RETF_VALID;
#endif

	return ret;
}


static ulog_interpreter_t base_ip[] = {
	{ .name = "raw", 
	  .interp = &_interp_raw, 
	  .key_num = 3, 
	  .result = raw_rets },
	{ .name = "oob", 
	  .interp = &_interp_oob, 
	  .key_num = 6, 
	  .result = oob_rets },
	{ .name  = "ip", 
	  .interp = &_interp_iphdr, 
	  .key_num = 10, 
	  .result = iphdr_rets },
	{ .name = "tcp", 
	  .interp = &_interp_tcphdr, 
	  .key_num = 17, 
	  .result = tcphdr_rets },
	{ .name = "icmp", 
	  .interp = &_interp_icmp, 
	  .key_num = 7, 
	  .result = icmphdr_rets },
	{ .name = "udp", 
	  .interp = &_interp_udp, 
	  .key_num = 4, 
	  .result = udphdr_rets },
	{ .name = "ahesp", 
	  .interp = &_interp_ahesp, 
	  .key_num = 1, 
	  .result = ahesphdr_rets },
	{ NULL, "", 0, NULL, 0, NULL }, 
};

void _base_reg_ip(void)
{
	ulog_interpreter_t *ip = base_ip;
	ulog_interpreter_t *p;

	for (p = ip; p->interp; p++) {
		register_interpreter(p);
	}
}

void _init(void)
{
	_base_reg_ip();
}
