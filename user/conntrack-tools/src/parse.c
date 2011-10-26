/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "network.h"

static int parse_u8(struct nf_conntrack *ct, int attr, void *data)
{
	u_int8_t *value = (u_int8_t *) data;
	nfct_set_attr_u8(ct, attr, *value);
}

static int parse_u16(struct nf_conntrack *ct, int attr, void *data)
{
	u_int16_t *value = (u_int16_t *) data;
	nfct_set_attr_u16(ct, attr, ntohs(*value));
}

static int parse_u32(struct nf_conntrack *ct, int attr, void *data)
{
	u_int32_t *value = (u_int32_t *) data;
	nfct_set_attr_u32(ct, attr, ntohl(*value));
}

typedef int (*parse)(struct nf_conntrack *ct, int attr, void *data);

parse h[ATTR_MAX] = {
	[ATTR_IPV4_SRC]		= parse_u32,
	[ATTR_IPV4_DST]		= parse_u32,
	[ATTR_L3PROTO]		= parse_u8,
	[ATTR_PORT_SRC]		= parse_u16,
	[ATTR_PORT_DST]		= parse_u16,
	[ATTR_L4PROTO]		= parse_u8,
	[ATTR_TCP_STATE]	= parse_u8,
	[ATTR_SNAT_IPV4]	= parse_u32,
	[ATTR_DNAT_IPV4]	= parse_u32,
	[ATTR_SNAT_PORT]	= parse_u16,
	[ATTR_DNAT_PORT]	= parse_u16,
	[ATTR_TIMEOUT]		= parse_u32,
	[ATTR_MARK]		= parse_u32,
	[ATTR_STATUS]		= parse_u32,
};

void parse_netpld(struct nf_conntrack *ct, struct netpld *pld, int *query)
{
	int len;
	struct netattr *attr;

	PLD_NETWORK2HOST(pld);
	len = pld->len;
	attr = PLD_DATA(pld);

	while (len > 0) {
		ATTR_NETWORK2HOST(attr);
		h[attr->nta_attr](ct, attr->nta_attr, NTA_DATA(attr));
		attr = NTA_NEXT(attr, len);
	}

	*query = pld->query;
}
