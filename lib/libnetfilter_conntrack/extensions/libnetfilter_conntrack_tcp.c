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
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

static const char *states[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"LISTEN"
};

static void parse_proto(struct nfattr *cda[], struct nfct_tuple *tuple)
{
	if (cda[CTA_PROTO_SRC_PORT-1])
		tuple->l4src.tcp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_SRC_PORT-1]);
	if (cda[CTA_PROTO_DST_PORT-1])
		tuple->l4dst.tcp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_DST_PORT-1]);
}

static void parse_protoinfo(struct nfattr *cda[], struct nfct_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_TCP_MAX];

	/*
	 * Listen to me carefully: This is easy to trigger with events ;). 
	 * The conntrack event messages don't always contain all the
	 * information about a conntrack, just those fields that have changed.
	 * So you can receive a message about a TCP connection with no bits 
	 * talking about the private protocol information. 
	 *
	 * 						--pablo 05/10/31
	 */
	if (!cda[CTA_PROTOINFO_TCP-1])
		return;
	
	nfnl_parse_nested(tb,CTA_PROTOINFO_TCP_MAX, cda[CTA_PROTOINFO_TCP-1]);
	
	if (tb[CTA_PROTOINFO_TCP_STATE-1])
                ct->protoinfo.tcp.state =
                        *(u_int8_t *)NFA_DATA(tb[CTA_PROTOINFO_TCP_STATE-1]);
}

static void build_tuple_proto(struct nfnlhdr *req, int size,
			      struct nfct_tuple *t)
{
	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_SRC_PORT,
		       &t->l4src.tcp.port, sizeof(u_int16_t));
	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_DST_PORT,
		       &t->l4dst.tcp.port, sizeof(u_int16_t));
}

static void build_protoinfo(struct nfnlhdr *req, int size, 
			    struct nfct_conntrack *ct)
{
	struct nfattr *nest_proto;

	nest_proto = nfnl_nest(&req->nlh, size, CTA_PROTOINFO_TCP);
	nfnl_addattr_l(&req->nlh, size, CTA_PROTOINFO_TCP_STATE,
		       &ct->protoinfo.tcp.state, sizeof(u_int8_t));
	nfnl_nest_end(&req->nlh, nest_proto);
}

static int print_protoinfo(char *buf, union nfct_protoinfo *protoinfo)
{
	return(sprintf(buf, "%s ", states[protoinfo->tcp.state]));
}

static int print_proto(char *buf, struct nfct_tuple *tuple)
{
	return(sprintf(buf, "sport=%u dport=%u ", htons(tuple->l4src.tcp.port),
					          htons(tuple->l4dst.tcp.port)));
}

static int compare(struct nfct_conntrack *ct1,
		   struct nfct_conntrack *ct2,
		   unsigned int flags)
{
	if (flags & TCP_ORIG_SPORT)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].l4src.tcp.port !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].l4src.tcp.port)
			return 0;
	if (flags & TCP_ORIG_DPORT)
		if (ct1->tuple[NFCT_DIR_ORIGINAL].l4dst.tcp.port !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].l4dst.tcp.port)
			return 0;
	if (flags & TCP_REPL_SPORT)
		if (ct1->tuple[NFCT_DIR_REPLY].l4src.tcp.port !=
		    ct2->tuple[NFCT_DIR_REPLY].l4src.tcp.port)
			return 0;
	if (flags & TCP_REPL_DPORT)
		if (ct1->tuple[NFCT_DIR_REPLY].l4dst.tcp.port !=
		    ct2->tuple[NFCT_DIR_REPLY].l4dst.tcp.port)
			return 0;
	if (flags & TCP_STATE)
		if (ct1->protoinfo.tcp.state != ct2->protoinfo.tcp.state)
			return 0;

	return 1;
}

static struct nfct_proto tcp = {
	.name 			= "tcp",
	.protonum		= IPPROTO_TCP,
	.parse_protoinfo	= parse_protoinfo,
	.parse_proto		= parse_proto,
	.build_tuple_proto	= build_tuple_proto,
	.build_protoinfo	= build_protoinfo,
	.print_protoinfo	= print_protoinfo,
	.print_proto		= print_proto,
	.compare		= compare,
	.version		= VERSION
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
	nfct_register_proto(&tcp);
}
