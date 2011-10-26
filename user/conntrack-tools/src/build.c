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

static void addattr(struct netpld *pld, int attr, const void *data, int len)
{
	struct netattr *nta;
	int tlen = NTA_LENGTH(len);

	nta = PLD_TAIL(pld);
	nta->nta_attr = htons(attr);
	nta->nta_len = htons(len);
	memcpy(NTA_DATA(nta), data, len);
	pld->len += NTA_ALIGN(tlen);
}

static void __build_u8(const struct nf_conntrack *ct,
		       struct netpld *pld,
		       int attr)
{
	u_int8_t data = nfct_get_attr_u8(ct, attr);
	addattr(pld, attr, &data, sizeof(u_int8_t));
}

static void __build_u16(const struct nf_conntrack *ct,
			struct netpld *pld,
			int attr)
{
	u_int16_t data = nfct_get_attr_u16(ct, attr);
	data = htons(data);
	addattr(pld, attr, &data, sizeof(u_int16_t));
}

static void __build_u32(const struct nf_conntrack *ct, 
			struct netpld *pld,
			int attr)
{
	u_int32_t data = nfct_get_attr_u32(ct, attr);
	data = htonl(data);
	addattr(pld, attr, &data, sizeof(u_int32_t));
}

static void __nat_build_u32(u_int32_t data, struct netpld *pld, int attr)
{
	data = htonl(data);
	addattr(pld, attr, &data, sizeof(u_int32_t));
}

static void __nat_build_u16(u_int16_t data, struct netpld *pld, int attr)
{
	data = htons(data);
	addattr(pld, attr, &data, sizeof(u_int16_t));
}

/* XXX: IPv6 and ICMP not supported */
void build_netpld(struct nf_conntrack *ct, struct netpld *pld, int query)
{
	if (nfct_attr_is_set(ct, ATTR_IPV4_SRC))
		__build_u32(ct, pld, ATTR_IPV4_SRC);
	if (nfct_attr_is_set(ct, ATTR_IPV4_DST))
		__build_u32(ct, pld, ATTR_IPV4_DST);
	if (nfct_attr_is_set(ct, ATTR_L3PROTO))
		__build_u8(ct, pld, ATTR_L3PROTO);
	if (nfct_attr_is_set(ct, ATTR_PORT_SRC))
		__build_u16(ct, pld, ATTR_PORT_SRC);
	if (nfct_attr_is_set(ct, ATTR_PORT_DST))
		__build_u16(ct, pld, ATTR_PORT_DST);
	if (nfct_attr_is_set(ct, ATTR_L4PROTO)) {
		u_int8_t proto;

		__build_u8(ct, pld, ATTR_L4PROTO);
		proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);
		if (proto == IPPROTO_TCP) {
			if (nfct_attr_is_set(ct, ATTR_TCP_STATE))
				__build_u8(ct, pld, ATTR_TCP_STATE);
		}
	}
	if (nfct_attr_is_set(ct, ATTR_TIMEOUT))
		__build_u32(ct, pld, ATTR_TIMEOUT);
	if (nfct_attr_is_set(ct, ATTR_MARK))
		__build_u32(ct, pld, ATTR_MARK);
	if (nfct_attr_is_set(ct, ATTR_STATUS))
		__build_u32(ct, pld, ATTR_STATUS);

	/*  NAT */
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
		u_int32_t data = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);
		__nat_build_u32(data, pld, ATTR_SNAT_IPV4);
	}
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
		u_int32_t data = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
		__nat_build_u32(data, pld, ATTR_DNAT_IPV4);
	}
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT)) {
		u_int16_t data = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);
		__nat_build_u16(data, pld, ATTR_SNAT_PORT);
	}
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT)) {
		u_int16_t data = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
		__nat_build_u16(data, pld, ATTR_DNAT_PORT);
	}

	pld->query = query;

	PLD_HOST2NETWORK(pld);
}
