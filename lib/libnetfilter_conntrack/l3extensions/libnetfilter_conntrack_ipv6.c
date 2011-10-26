/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> /* For htons */
#include <arpa/inet.h>
#include <libnetfilter_conntrack/linux_nfnetlink_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_l3extensions.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_ipv6.h>

#ifndef HAVE_INET_NTOP_IPV6
#warning "inet_ntop does not support IPv6"
#endif

static void parse_proto(struct nfattr *cda[], struct nfct_tuple *tuple)
{
	if (cda[CTA_IP_V6_SRC-1])
		memcpy(tuple->src.v6, NFA_DATA(cda[CTA_IP_V6_SRC-1]), 
		       sizeof(u_int32_t)*4);

	if (cda[CTA_IP_V6_DST-1])
		memcpy(tuple->dst.v6, NFA_DATA(cda[CTA_IP_V6_DST-1]),
		       sizeof(u_int32_t)*4);
}

static void build_tuple_proto(struct nfnlhdr *req, int size,
                              struct nfct_tuple *t)
{
	nfnl_addattr_l(&req->nlh, size, CTA_IP_V6_SRC, &t->src.v6,
		       sizeof(u_int32_t)*4);
	nfnl_addattr_l(&req->nlh, size, CTA_IP_V6_DST, &t->dst.v6,
		       sizeof(u_int32_t)*4);
}

static int print_proto(char *buf, struct nfct_tuple *tuple)
{
	struct in6_addr src;
	struct in6_addr dst;
	char tmp[INET6_ADDRSTRLEN];
	int size;

	memcpy(&src.in6_u, tuple->src.v6, sizeof(struct in6_addr));
	memcpy(&dst.in6_u, tuple->dst.v6, sizeof(struct in6_addr));

	if (!inet_ntop(AF_INET6, &src, tmp, sizeof(tmp)))
		return 0;
	size = sprintf(buf, "src=%s ", tmp);
	if (!inet_ntop(AF_INET6, &dst, tmp, sizeof(tmp)))
		return 0;
	size += sprintf(buf + size, "dst=%s ", tmp);

	return size;
}

static int compare(struct nfct_conntrack *ct1,
		   struct nfct_conntrack *ct2,
		   unsigned int flags)
{
	if (flags & IPV6_ORIG)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].l3protonum !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].l3protonum)
			return 0;
	if (flags & IPV6_REPL)
		if (ct1->tuple[NFCT_DIR_REPLY].l3protonum !=
		    ct2->tuple[NFCT_DIR_REPLY].l3protonum)
			return 0;
	if (flags & IPV6_ORIG_SRC)
		if (memcmp(ct1->tuple[NFCT_DIR_ORIGINAL].src.v6,
			   ct2->tuple[NFCT_DIR_ORIGINAL].src.v6,
			   sizeof(u_int32_t)*4) == 0)
			return 0;
	if (flags & IPV6_ORIG_DST)
		if (memcmp(ct1->tuple[NFCT_DIR_ORIGINAL].dst.v6,
			   ct2->tuple[NFCT_DIR_ORIGINAL].dst.v6,
			   sizeof(u_int32_t)*4) == 0)
			return 0;
	if (flags & IPV6_REPL_SRC)
		if (memcmp(ct1->tuple[NFCT_DIR_REPLY].src.v6,
			   ct2->tuple[NFCT_DIR_REPLY].src.v6,
			   sizeof(u_int32_t)*4) == 0)
			return 0;
	if (flags & IPV6_REPL_DST)
		if (memcmp(ct1->tuple[NFCT_DIR_REPLY].dst.v6,
			   ct2->tuple[NFCT_DIR_REPLY].dst.v6,
			   sizeof(u_int32_t)*4) == 0)
			return 0;

	return 1;
}

static struct nfct_l3proto ipv6 = {
	.name			= "ipv6",
	.protonum		= AF_INET6,
	.parse_proto		= parse_proto,
	.build_tuple_proto	= build_tuple_proto,
	.print_proto		= print_proto,
	.compare		= compare,
	.version		= VERSION
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
        nfct_register_l3proto(&ipv6);
}
