/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

static void set_attr_orig_ipv4_src(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].src.v4 = *((u_int32_t *) value);
}

static void set_attr_orig_ipv4_dst(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].dst.v4 = *((u_int32_t *) value);
}

static void set_attr_repl_ipv4_src(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_REPL].src.v4 = *((u_int32_t *) value);
}

static void set_attr_repl_ipv4_dst(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_REPL].dst.v4 = *((u_int32_t *) value);
}

static void set_attr_orig_ipv6_src(struct nf_conntrack *ct, const void *value)
{
	memcpy(&ct->tuple[__DIR_ORIG].src.v6, value, sizeof(u_int32_t)*4);
}

static void set_attr_orig_ipv6_dst(struct nf_conntrack *ct, const void *value)
{
	memcpy(&ct->tuple[__DIR_ORIG].dst.v6, value, sizeof(u_int32_t)*4);
}

static void set_attr_repl_ipv6_src(struct nf_conntrack *ct, const void *value)
{
	memcpy(&ct->tuple[__DIR_REPL].src.v6, value, sizeof(u_int32_t)*4);
}

static void set_attr_repl_ipv6_dst(struct nf_conntrack *ct, const void *value)
{
	memcpy(&ct->tuple[__DIR_REPL].dst.v6, value, sizeof(u_int32_t)*4);
}

static void set_attr_orig_port_src(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].l4src.all = *((u_int16_t *) value);
}

static void set_attr_orig_port_dst(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].l4dst.all = *((u_int16_t *) value);
}

static void set_attr_repl_port_src(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_REPL].l4src.all = *((u_int16_t *) value);
}

static void set_attr_repl_port_dst(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_REPL].l4dst.all = *((u_int16_t *) value);
}

static void set_attr_icmp_type(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].l4dst.icmp.type = *((u_int8_t *) value);
}

static void set_attr_icmp_code(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].l4dst.icmp.code = *((u_int8_t *) value);
}

static void set_attr_icmp_id(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].l4src.icmp.id = *((u_int16_t *) value);
}

static void set_attr_orig_l3proto(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].l3protonum = *((u_int8_t *) value);
}

static void set_attr_repl_l3proto(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_REPL].l3protonum = *((u_int8_t *) value);
}

static void set_attr_orig_l4proto(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_ORIG].protonum = *((u_int8_t *) value);
}

static void set_attr_repl_l4proto(struct nf_conntrack *ct, const void *value)
{
	ct->tuple[__DIR_REPL].protonum = *((u_int8_t *) value);
}

static void set_attr_tcp_state(struct nf_conntrack *ct, const void *value)
{
	ct->protoinfo.tcp.state = *((u_int8_t *) value);
}

static void set_attr_snat_ipv4(struct nf_conntrack *ct, const void *value)
{
	ct->snat.min_ip = ct->snat.max_ip = *((u_int32_t *) value);
}

static void set_attr_dnat_ipv4(struct nf_conntrack *ct, const void *value)
{
	ct->dnat.min_ip = ct->snat.max_ip = *((u_int32_t *) value);
}

static void set_attr_snat_port(struct nf_conntrack *ct, const void *value)
{
	ct->snat.l4min.all = ct->snat.l4max.all = *((u_int16_t *) value);
}

static void set_attr_dnat_port(struct nf_conntrack *ct, const void *value)
{
	ct->dnat.l4min.all = ct->dnat.l4max.all = *((u_int16_t *) value);
}

static void set_attr_timeout(struct nf_conntrack *ct, const void *value)
{
	ct->timeout = *((u_int32_t *) value);
}

static void set_attr_mark(struct nf_conntrack *ct, const void *value)
{
	ct->mark = *((u_int32_t *) value);
}

static void set_attr_id(struct nf_conntrack *ct, const void *value)
{
	ct->id = *((u_int32_t *) value);
}

static void set_attr_status(struct nf_conntrack *ct, const void *value)
{
	ct->status = *((u_int32_t *) value);
}

set_attr set_attr_array[] = {
	[ATTR_ORIG_IPV4_SRC]	= set_attr_orig_ipv4_src,
	[ATTR_ORIG_IPV4_DST] 	= set_attr_orig_ipv4_dst,
	[ATTR_REPL_IPV4_SRC]	= set_attr_repl_ipv4_src,
	[ATTR_REPL_IPV4_DST]	= set_attr_repl_ipv4_dst,
	[ATTR_ORIG_IPV6_SRC]	= set_attr_orig_ipv6_src,
	[ATTR_ORIG_IPV6_DST]	= set_attr_orig_ipv6_dst,
	[ATTR_REPL_IPV6_SRC]	= set_attr_repl_ipv6_src,
	[ATTR_REPL_IPV6_DST]	= set_attr_repl_ipv6_dst,
	[ATTR_ORIG_PORT_SRC]	= set_attr_orig_port_src,
	[ATTR_ORIG_PORT_DST]	= set_attr_orig_port_dst,
	[ATTR_REPL_PORT_SRC]	= set_attr_repl_port_src,
	[ATTR_REPL_PORT_DST]	= set_attr_repl_port_dst,
	[ATTR_ICMP_TYPE]	= set_attr_icmp_type,
	[ATTR_ICMP_CODE]	= set_attr_icmp_code,
	[ATTR_ICMP_ID]		= set_attr_icmp_id,
	[ATTR_ORIG_L3PROTO]	= set_attr_orig_l3proto,
	[ATTR_REPL_L3PROTO]	= set_attr_repl_l3proto,
	[ATTR_ORIG_L4PROTO]	= set_attr_orig_l4proto,
	[ATTR_REPL_L4PROTO]	= set_attr_repl_l4proto,
	[ATTR_TCP_STATE]	= set_attr_tcp_state,
	[ATTR_SNAT_IPV4]	= set_attr_snat_ipv4,
	[ATTR_DNAT_IPV4]	= set_attr_dnat_ipv4,
	[ATTR_SNAT_PORT]	= set_attr_snat_port,
	[ATTR_DNAT_PORT]	= set_attr_dnat_port,
	[ATTR_TIMEOUT]		= set_attr_timeout,
	[ATTR_MARK]		= set_attr_mark,
	[ATTR_ID]		= set_attr_id,
	[ATTR_STATUS]		= set_attr_status,
};
