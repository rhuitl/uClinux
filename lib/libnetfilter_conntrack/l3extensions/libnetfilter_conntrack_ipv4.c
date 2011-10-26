/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h> /* For htons */
#include <libnetfilter_conntrack/linux_nfnetlink_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_l3extensions.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_ipv4.h>

static void parse_proto(struct nfattr *cda[], struct nfct_tuple *tuple)
{
	if (cda[CTA_IP_V4_SRC-1])
		tuple->src.v4 = *(u_int32_t *)NFA_DATA(cda[CTA_IP_V4_SRC-1]);

	if (cda[CTA_IP_V4_DST-1])
		tuple->dst.v4 = *(u_int32_t *)NFA_DATA(cda[CTA_IP_V4_DST-1]);
}

static void build_tuple_proto(struct nfnlhdr *req, int size,
                              struct nfct_tuple *t)
{
	nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_SRC, &t->src.v4,
		       sizeof(u_int32_t));
	nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_DST, &t->dst.v4,
		       sizeof(u_int32_t));
}

static int print_proto(char *buf, struct nfct_tuple *tuple)
{
	struct in_addr src = { .s_addr = tuple->src.v4 };
	struct in_addr dst = { .s_addr = tuple->dst.v4 };
	int size;

	size = sprintf(buf, "src=%s ", inet_ntoa(src));
	size += sprintf(buf+size, "dst=%s ", inet_ntoa(dst));

	return size;
}

static int compare(struct nfct_conntrack *ct1,
		   struct nfct_conntrack *ct2,
		   unsigned int flags)
{
	if (flags & IPV4_ORIG)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].l3protonum !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].l3protonum)
			return 0;
	if (flags & IPV4_REPL)
		if (ct1->tuple[NFCT_DIR_REPLY].l3protonum !=
		    ct2->tuple[NFCT_DIR_REPLY].l3protonum)
			return 0;
	if (flags & IPV4_ORIG_SRC)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].src.v4 !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].src.v4)
			return 0;
	if (flags & IPV4_ORIG_DST)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].dst.v4 !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].dst.v4)
			return 0;
	if (flags & IPV4_REPL_SRC)
		if (ct1->tuple[NFCT_DIR_REPLY].src.v4 !=
		    ct2->tuple[NFCT_DIR_REPLY].src.v4)
			return 0;
	if (flags & IPV4_REPL_DST)
		if (ct1->tuple[NFCT_DIR_REPLY].dst.v4 !=
		    ct2->tuple[NFCT_DIR_REPLY].dst.v4)
			return 0;

	return 1;
}

static struct nfct_l3proto ipv4 = {
	.name			= "ipv4",
	.protonum		= AF_INET,
	.parse_proto		= parse_proto,
	.build_tuple_proto	= build_tuple_proto,
	.print_proto		= print_proto,
	.compare		= compare,
	.version		= VERSION
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
        nfct_register_l3proto(&ipv4);
}
