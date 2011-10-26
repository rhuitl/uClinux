/* ulogd_MAC.c, Version $Revision$
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
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 
 * $Id$
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
#include <ulogd/ipfix_protocol.h>


/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static struct ulogd_key iphdr_rets[] = {
	{ 
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE, 
		.name = "ip.saddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.daddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.protocol", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.tos", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_classOfServiceIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ttl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ipTimeToLive,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.totlen", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_totalLengthIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ihl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_internetHeaderLengthIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.csum", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.id", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_identificationIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.fragoff", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_fragmentOffsetIPv4,
		},
	},

	/* 10 */

	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSourcePort,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpDestinationPort,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.seq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSequenceNumber,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.ackseq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpAcknowledgementNumber,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.offset",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.reserved",
	}, 
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.window",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpWindowSize,
		},
	},
	{
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urg", 
	},
	{
		.type = ULOGD_RET_UINT16, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urgp",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpUrgentPointer,
		},
	},
	{
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.ack", 
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.psh",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.rst",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.syn",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.fin",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res1",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res2",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.csum",
	},

	/* 27 */

	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = IPFIX_udpSourcePort,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_udpDestinationPort,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.len", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.csum",
	},

	/* 31 */


	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.type", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpTypeIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.code", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpCodeIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoid", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoseq",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.gateway", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.fragmtu", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.csum",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ahesp.spi",
	},

	/* 39 */

};

/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/

static int _interp_tcp(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = &pi->output.keys[10];
	struct iphdr *iph = (struct iphdr *)
				pi->input.keys[0].u.source->u.value.ptr;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct tcphdr *tcph = (struct tcphdr *) protoh;

	if (iph->protocol != IPPROTO_TCP)
		return 0;
	
	ret[0].u.value.ui16 = ntohs(tcph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui16 = ntohs(tcph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].u.value.ui32 = ntohl(tcph->seq);
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].u.value.ui32 = ntohl(tcph->ack_seq);
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].u.value.ui8 = ntohs(tcph->doff);
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].u.value.ui8 = ntohs(tcph->res1);
	ret[5].flags |= ULOGD_RETF_VALID;
	ret[6].u.value.ui16 = ntohs(tcph->window);
	ret[6].flags |= ULOGD_RETF_VALID;

	ret[7].u.value.b = tcph->urg;
	ret[7].flags |= ULOGD_RETF_VALID;
	if (tcph->urg) {
		ret[8].u.value.ui16 = ntohs(tcph->urg_ptr);
		ret[8].flags |= ULOGD_RETF_VALID;
	}
	ret[9].u.value.b = tcph->ack;
	ret[9].flags |= ULOGD_RETF_VALID;
	ret[10].u.value.b = tcph->psh;
	ret[10].flags |= ULOGD_RETF_VALID;
	ret[11].u.value.b = tcph->rst;
	ret[11].flags |= ULOGD_RETF_VALID;
	ret[12].u.value.b = tcph->syn;
	ret[12].flags |= ULOGD_RETF_VALID;
	ret[13].u.value.b = tcph->fin;
	ret[13].flags |= ULOGD_RETF_VALID;
	ret[14].u.value.b = tcph->res1;
	ret[14].flags |= ULOGD_RETF_VALID;
	ret[15].u.value.b = tcph->res2;
	ret[15].flags |= ULOGD_RETF_VALID;
	ret[16].u.value.ui16 = ntohs(tcph->check);
	ret[16].u.value.ui16 = ULOGD_RETF_VALID;
	
	return 0;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/

static int _interp_udp(struct ulogd_pluginstance *pi)
		
{
	struct ulogd_key *ret = &pi->output.keys[27];
	struct iphdr *iph = (struct iphdr *) 
				pi->input.keys[0].u.source->u.value.ptr;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct udphdr *udph = protoh;

	if (iph->protocol != IPPROTO_UDP)
		return 0;

	ret[0].u.value.ui16 = ntohs(udph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui16 = ntohs(udph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].u.value.ui16 = ntohs(udph->len);
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].u.value.ui16 = ntohs(udph->check);
	ret[3].flags |= ULOGD_RETF_VALID;
	
	return 0;
}

/***********************************************************************
 * 			ICMP HEADER
 ***********************************************************************/

static int _interp_icmp(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = &pi->output.keys[31];
	struct iphdr *iph = (struct iphdr *) 
				pi->input.keys[0].u.source->u.value.ptr;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct icmphdr *icmph = protoh;

	if (iph->protocol != IPPROTO_ICMP)
		return 0;
	
	ret[0].u.value.ui8 = icmph->type;
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui8 = icmph->code;
	ret[1].flags |= ULOGD_RETF_VALID;

	switch (icmph->type) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			ret[2].u.value.ui16 = ntohs(icmph->un.echo.id);
			ret[2].flags |= ULOGD_RETF_VALID;
			ret[3].u.value.ui16 = ntohs(icmph->un.echo.sequence);
			ret[3].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_REDIRECT:
		case ICMP_PARAMETERPROB:
			ret[4].u.value.ui32 = ntohl(icmph->un.gateway);
			ret[4].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_DEST_UNREACH:
			if (icmph->code == ICMP_FRAG_NEEDED) {
				ret[5].u.value.ui16 = ntohs(icmph->un.frag.mtu);
				ret[5].flags |= ULOGD_RETF_VALID;
			}
			break;
	}
	ret[6].u.value.ui16 = icmph->checksum;
	ret[6].flags |= ULOGD_RETF_VALID;

	return 0;
}

/***********************************************************************
 * 			IPSEC HEADER 
 ***********************************************************************/

static int _interp_ahesp(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = &pi->output.keys[38];
	struct iphdr *iph = (struct iphdr *) 
				pi->input.keys[0].u.source->u.value.ptr;
	void *protoh = (u_int32_t *)iph + iph->ihl;

#if 0
	struct esphdr *esph = protoh;

	if (iph->protocol != IPPROTO_ESP)
		return NULL;

	ret[0].u.value.ui32 = ntohl(esph->spi);
	ret[0].flags |= ULOGD_RETF_VALID;
#endif

	return 0;
}

static int _interp_iphdr(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct iphdr *iph = (struct iphdr *) 
				pi->input.keys[0].u.source->u.value.ptr;

	ret[0].u.value.ui32 = ntohl(iph->saddr);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui32 = ntohl(iph->daddr);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].u.value.ui8 = iph->protocol;
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].u.value.ui8 = iph->tos;
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].u.value.ui8 = iph->ttl;
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].u.value.ui16 = ntohs(iph->tot_len);
	ret[5].flags |= ULOGD_RETF_VALID;
	ret[6].u.value.ui8 = iph->ihl;
	ret[6].flags |= ULOGD_RETF_VALID;
	ret[7].u.value.ui16 = ntohs(iph->check);
	ret[7].flags |= ULOGD_RETF_VALID;
	ret[8].u.value.ui16 = ntohs(iph->id);
	ret[8].flags |= ULOGD_RETF_VALID;
	ret[9].u.value.ui16 = ntohs(iph->frag_off);
	ret[9].flags |= ULOGD_RETF_VALID;

	switch (iph->protocol) {
		case IPPROTO_TCP:
			_interp_tcp(pi);
			break;
		case IPPROTO_UDP:
			_interp_udp(pi);
			break;
		case IPPROTO_ICMP:
			_interp_icmp(pi);
			break;
		case IPPROTO_AH:
		case IPPROTO_ESP:
			_interp_ahesp(pi);
			break;
	}


	return 0;
}

static struct ulogd_key base_inp[] = {
	{ 
		.type = ULOGD_RET_RAW,
		.name = "raw.pkt", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_NETFILTER, 
			.field_id = 1 
		},
	},
};

static struct ulogd_plugin base_plugin = {
	.name = "BASE",
	.input = {
		.keys = base_inp,
		.num_keys = ARRAY_SIZE(base_inp),
		.type = ULOGD_DTYPE_RAW,
		},
	.output = {
		.keys = iphdr_rets,
		.num_keys = ARRAY_SIZE(iphdr_rets),
		.type = ULOGD_DTYPE_PACKET,
		},
	.interp = &_interp_iphdr,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&base_plugin);
}
