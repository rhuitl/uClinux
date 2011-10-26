/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> /* For htons */
#include <libnetfilter_conntrack/linux_nfnetlink_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_extensions.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_icmp.h>

static void parse_proto(struct nfattr *cda[], struct nfct_tuple *tuple)
{
	if (cda[CTA_PROTO_ICMP_TYPE-1])
		tuple->l4dst.icmp.type =
			*(u_int8_t *)NFA_DATA(cda[CTA_PROTO_ICMP_TYPE-1]);

	if (cda[CTA_PROTO_ICMP_CODE-1])
		tuple->l4dst.icmp.code =
			*(u_int8_t *)NFA_DATA(cda[CTA_PROTO_ICMP_CODE-1]);

	if (cda[CTA_PROTO_ICMP_ID-1])
		tuple->l4src.icmp.id =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_ICMP_ID-1]);
}

static void build_tuple_proto(struct nfnlhdr *req, int size,
			      struct nfct_tuple *t)
{
	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_CODE,
		       &t->l4dst.icmp.code, sizeof(u_int8_t));
	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_TYPE,
		       &t->l4dst.icmp.type, sizeof(u_int8_t));
	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_ID,
		       &t->l4src.icmp.id, sizeof(u_int16_t));
}

static int print_proto(char *buf, struct nfct_tuple *t)
{
	/* The ID only makes sense some ICMP messages but we want to
	 * display the same output that /proc/net/ip_conntrack does */
	return (sprintf(buf, "type=%d code=%d id=%d ",t->l4dst.icmp.type,
						      t->l4dst.icmp.code,
						      ntohs(t->l4src.icmp.id)));
}

static int compare(struct nfct_conntrack *ct1,
		   struct nfct_conntrack *ct2,
		   unsigned int flags)
{
	if (flags & ICMP_TYPE)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].l4dst.icmp.type !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].l4dst.icmp.type)
			return 0;
	if (flags & ICMP_CODE)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].l4dst.icmp.code !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].l4dst.icmp.code)
			return 0;
	if (flags & ICMP_ID)
		if (ct1->tuple[NFCT_DIR_REPLY].l4src.icmp.id !=
		    ct2->tuple[NFCT_DIR_REPLY].l4src.icmp.id)
			return 0;

	return 1;
}

static struct nfct_proto icmp = {
	.name 			= "icmp",
	.protonum		= IPPROTO_ICMP,
	.parse_proto		= parse_proto,
	.build_tuple_proto	= build_tuple_proto,
	.print_proto		= print_proto,
	.compare		= compare,
	.version		= VERSION
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
	nfct_register_proto(&icmp);
}
