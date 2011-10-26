/*
 * (C) 2005-2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *                  Harald Welte <laforge@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include "linux_list.h"
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_l3extensions.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_extensions.h>

#include "internal.h"

#define NFCT_BUFSIZE 4096

static char *lib_dir = LIBNETFILTER_CONNTRACK_DIR;
static LIST_HEAD(proto_list);
static LIST_HEAD(l3proto_list);
static char *proto2str[IPPROTO_MAX] = {
	[IPPROTO_TCP] = "tcp",
        [IPPROTO_UDP] = "udp",
        [IPPROTO_ICMP] = "icmp",
        [IPPROTO_SCTP] = "sctp"
};
static char *l3proto2str[AF_MAX] = {
	[AF_INET] = "ipv4",
	[AF_INET6] = "ipv6"
};
static struct nfct_proto *findproto(char *name);
static struct nfct_l3proto *findl3proto(char *name);

/* handler used for nfnl_listen */
static int callback_handler(struct sockaddr_nl *nladdr,
			    struct nlmsghdr *n, void *arg)
{
	struct nfct_handle *cth = (struct nfct_handle *) arg;
	int ret;

	if (NFNL_SUBSYS_ID(n->nlmsg_type) != NFNL_SUBSYS_CTNETLINK &&
	    NFNL_SUBSYS_ID(n->nlmsg_type) != NFNL_SUBSYS_CTNETLINK_EXP) {
		nfnl_dump_packet(n, n->nlmsg_len, "callback_handler");
		return 0;
	}

	if (!cth)
		return -ENODEV;

	if (!cth->handler)
		return -ENODEV;

	ret = cth->handler(cth, n, NULL);

	return ret;
}

struct nfct_handle *nfct_open_nfnl(struct nfnl_handle *nfnlh,
				   u_int8_t subsys_id,
				   unsigned int subscriptions)
{
	struct nfct_handle *cth;

	cth = (struct nfct_handle *) malloc(sizeof(struct nfct_handle));
	if (!cth)
		return NULL;
	
	memset(cth, 0, sizeof(*cth));
	cth->nfnlh = nfnlh;

	if (subsys_id == 0 || subsys_id == NFNL_SUBSYS_CTNETLINK) {
		cth->nfnlssh_ct = nfnl_subsys_open(cth->nfnlh, 
						   NFNL_SUBSYS_CTNETLINK, 
						   IPCTNL_MSG_MAX,
						   subscriptions);
		if (!cth->nfnlssh_ct)
			goto out_free;
	}

	if (subsys_id == 0 || subsys_id == NFNL_SUBSYS_CTNETLINK_EXP) {
		cth->nfnlssh_exp = nfnl_subsys_open(cth->nfnlh,
						    NFNL_SUBSYS_CTNETLINK_EXP,
						    IPCTNL_MSG_EXP_MAX,
						    subscriptions);
		if (!cth->nfnlssh_exp)
			goto out_free;
	}

	return cth;

out_free:
	if (cth->nfnlssh_exp) {
		nfnl_subsys_close(cth->nfnlssh_exp);
		cth->nfnlssh_exp = NULL;
	}
	if (cth->nfnlssh_ct) {
		nfnl_subsys_close(cth->nfnlssh_ct);
		cth->nfnlssh_ct = NULL;
	}
	free(cth);
	return NULL;
}

struct nfct_handle *nfct_open(u_int8_t subsys_id, unsigned subscriptions)
{
	struct nfnl_handle *nfnlh = nfnl_open();
	struct nfct_handle *nfcth;

	if (!nfnlh)
		return NULL;

	nfcth = nfct_open_nfnl(nfnlh, subsys_id, subscriptions);
	if (!nfcth)
		nfnl_close(nfnlh);

	return nfcth;
}

int nfct_close(struct nfct_handle *cth)
{
	int err;

	if (cth->nfnlssh_exp) {
		nfnl_subsys_close(cth->nfnlssh_exp);
		cth->nfnlssh_exp = NULL;
	}
	if (cth->nfnlssh_ct) {
		nfnl_subsys_close(cth->nfnlssh_ct);
		cth->nfnlssh_ct = NULL;
	}

	/* required by the new API */
	cth->cb = NULL;
	free(cth->nfnl_cb.data);

	cth->nfnl_cb.call = NULL; 
	cth->nfnl_cb.data = NULL;
	cth->nfnl_cb.attr_count = 0;

	err = nfnl_close(cth->nfnlh);
	free(cth);

	return err;
}

int nfct_fd(struct nfct_handle *cth)
{
	return nfnl_fd(cth->nfnlh);
}

const struct nfnl_handle *nfct_nfnlh(struct nfct_handle *cth)
{
	return cth->nfnlh;
}

void nfct_register_callback(struct nfct_handle *cth, nfct_callback callback,
			    void *data)
{
	cth->callback = callback;
	cth->callback_data = data;
}

void nfct_unregister_callback(struct nfct_handle *cth)
{
	cth->callback = NULL;
	cth->callback_data = NULL;
}

static void nfct_build_tuple_ip(struct nfnlhdr *req, int size, 
				struct nfct_tuple *t)
{
	struct nfattr *nest;
	struct nfct_l3proto *h;

	nest = nfnl_nest(&req->nlh, size, CTA_TUPLE_IP);

	h = findl3proto(l3proto2str[t->l3protonum]);
	if (h && h->build_tuple_proto)
		h->build_tuple_proto(req, size, t);

	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_tuple_proto(struct nfnlhdr *req, int size,
				   struct nfct_tuple *t)
{
	struct nfct_proto *h;
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_TUPLE_PROTO);

	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_NUM, &t->protonum,
		       sizeof(u_int8_t));

	h = findproto(proto2str[t->protonum]);

	if (h && h->build_tuple_proto)
		h->build_tuple_proto(req, size, t);

	nfnl_nest_end(&req->nlh, nest);
}

void nfct_build_tuple(struct nfnlhdr *req, int size, 
		      struct nfct_tuple *t, int type)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, type);

	nfct_build_tuple_ip(req, size, t);
	nfct_build_tuple_proto(req, size, t);

	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_protoinfo(struct nfnlhdr *req, int size,
				 struct nfct_conntrack *ct)
{
	struct nfattr *nest;
	struct nfct_proto *h;

	h = findproto(proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum]);
	if (h && h->build_protoinfo) {
		nest = nfnl_nest(&req->nlh, size, CTA_PROTOINFO);
		h->build_protoinfo(req, size, ct);
		nfnl_nest_end(&req->nlh, nest);
	}
}

static void nfct_build_protonat(struct nfnlhdr *req, int size,
				struct nfct_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_PROTO);

	switch (ct->tuple[NFCT_DIR_ORIGINAL].protonum) {
#if 0
	case IPPROTO_TCP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_TCP_MIN,
			       &ct->nat.l4min.tcp.port, sizeof(u_int16_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_TCP_MAX,
			       &ct->nat.l4max.tcp.port, sizeof(u_int16_t));
		break;
	case IPPROTO_UDP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_UDP_MIN,
			       &ct->nat.l4min.udp.port, sizeof(u_int16_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_UDP_MAX,
			       &ct->nat.l4max.udp.port, sizeof(u_int16_t));
		break;
#endif
	}
	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_nat(struct nfnlhdr *req, int size,
			   struct nfct_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT);

	nfnl_addattr_l(&req->nlh, size, CTA_NAT_MINIP,
		       &ct->nat.min_ip, sizeof(u_int32_t));
	
	if (ct->nat.min_ip != ct->nat.max_ip)
		nfnl_addattr_l(&req->nlh, size, CTA_NAT_MAXIP,
			       &ct->nat.max_ip, sizeof(u_int32_t));

	if (ct->nat.l4min.all != ct->nat.l4max.all)
		nfct_build_protonat(req, size, ct);

	nfnl_nest_end(&req->nlh, nest);
}

void nfct_dump_tuple(struct nfct_tuple *tp)
{
	struct in_addr src = { .s_addr = tp->src.v4 };
	struct in_addr dst = { .s_addr = tp->dst.v4 };
	
	fprintf(stdout, "tuple %p: %u %s:%hu -> ", tp, tp->protonum,
						   inet_ntoa(src),
						   ntohs(tp->l4src.all));

	fprintf(stdout, "%s:%hu\n", inet_ntoa(dst), ntohs(tp->l4dst.all));
}

static struct nfct_proto *findproto(char *name)
{
	struct list_head *i;
	struct nfct_proto *cur = NULL, *handler = NULL;

	if (!name) 
		return handler;

	lib_dir = getenv("LIBNETFILTER_CONNTRACK_DIR");
	if (!lib_dir)
		lib_dir = LIBNETFILTER_CONNTRACK_DIR;

	list_for_each(i, &proto_list) {
		cur = (struct nfct_proto *) i;
		if (strcmp(cur->name, name) == 0) {
			handler = cur;
			break;
		}
	}

	if (!handler) {
		char path[sizeof("nfct_proto_.so") + strlen(VERSION)
			 + strlen(name) + strlen(lib_dir)];
                sprintf(path, "%s/nfct_proto_%s-%s.so", lib_dir, name, VERSION);
		if (dlopen(path, RTLD_NOW))
			handler = findproto(name);
		else
			fprintf(stderr, "%s\n", dlerror());
	}

	return handler;
}

static struct nfct_l3proto *findl3proto(char *name)
{
	struct list_head *i;
	struct nfct_l3proto *cur = NULL, *handler = NULL;

	if (!name) 
		return handler;

	lib_dir = getenv("LIBNETFILTER_CONNTRACK_DIR");
	if (!lib_dir)
		lib_dir = LIBNETFILTER_CONNTRACK_DIR;

	list_for_each(i, &l3proto_list) {
		cur = (struct nfct_l3proto *) i;
		if (strcmp(cur->name, name) == 0) {
			handler = cur;
			break;
		}
	}

	if (!handler) {
		char path[sizeof("nfct_l3proto_.so") + strlen(VERSION)
			 + strlen(name) + strlen(lib_dir)];
                sprintf(path, "%s/nfct_l3proto_%s-%s.so",lib_dir,name,VERSION);
		if (dlopen(path, RTLD_NOW))
			handler = findl3proto(name);
		else
			fprintf(stderr, "%s\n", dlerror());
	}

	return handler;
}

int nfct_sprintf_status_assured(char *buf, struct nfct_conntrack *ct)
{
	int size = 0;
	
	if (ct->status & IPS_ASSURED)
		size = sprintf(buf, "[ASSURED] ");

	return size;
}

int nfct_sprintf_status_seen_reply(char *buf, struct nfct_conntrack *ct)
{
	int size = 0;
	
        if (!(ct->status & IPS_SEEN_REPLY))
                size = sprintf(buf, "[UNREPLIED] ");

	return size;
}

static void parse_ip(struct nfattr *attr, struct nfct_tuple *tuple)
{
	struct nfattr *tb[CTA_IP_MAX];
	struct nfct_l3proto *h;

        nfnl_parse_nested(tb, CTA_IP_MAX, attr);
	h = findl3proto(l3proto2str[tuple->l3protonum]);
	if (h && h->parse_proto)
		h->parse_proto(tb, tuple);
}

static void parse_proto(struct nfattr *attr, struct nfct_tuple *tuple)
{
	struct nfattr *tb[CTA_PROTO_MAX];
	struct nfct_proto *h;

	nfnl_parse_nested(tb, CTA_PROTO_MAX, attr);
	if (tb[CTA_PROTO_NUM-1])
		tuple->protonum = *(u_int8_t *)NFA_DATA(tb[CTA_PROTO_NUM-1]);
	
	h = findproto(proto2str[tuple->protonum]);
	if (h && h->parse_proto)
		h->parse_proto(tb, tuple);
}

static void parse_tuple(struct nfattr *attr, struct nfct_tuple *tuple)
{
	struct nfattr *tb[CTA_TUPLE_MAX];

	nfnl_parse_nested(tb, CTA_TUPLE_MAX, attr);

	if (tb[CTA_TUPLE_IP-1])
		parse_ip(tb[CTA_TUPLE_IP-1], tuple);
	if (tb[CTA_TUPLE_PROTO-1])
		parse_proto(tb[CTA_TUPLE_PROTO-1], tuple);
}

static void parse_mask(struct nfattr *attr, struct nfct_tuple *tuple,
		       u_int8_t l3protonum, u_int16_t protonum)
{
	struct nfattr *cda[CTA_TUPLE_MAX];

	nfnl_parse_nested(cda, CTA_TUPLE_MAX, attr);

	if (cda[CTA_TUPLE_IP-1]) {
		struct nfattr *tb[CTA_IP_MAX];
		struct nfct_l3proto *h;

		nfnl_parse_nested(tb, CTA_IP_MAX, cda[CTA_TUPLE_IP-1]);
		h = findl3proto(l3proto2str[l3protonum]);
		if (h && h->parse_proto)
			h->parse_proto(tb, tuple);
	}
	if (cda[CTA_TUPLE_PROTO-1]) {
		struct nfattr *tb[CTA_PROTO_MAX];
		struct nfct_proto *h;

		nfnl_parse_nested(tb, CTA_PROTO_MAX, cda[CTA_TUPLE_PROTO-1]);
		if (tb[CTA_PROTO_NUM-1])
			tuple->protonum = 
				*(u_int8_t *)NFA_DATA(tb[CTA_PROTO_NUM-1]);

		h = findproto(proto2str[protonum]);
		if (h && h->parse_proto)
			h->parse_proto(tb, tuple);
	}
}

static void parse_protoinfo(struct nfattr *attr, struct nfct_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_MAX];
	struct nfct_proto *h;

	nfnl_parse_nested(tb,CTA_PROTOINFO_MAX, attr);

	h = findproto(proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum]);
        if (h && h->parse_protoinfo)
		h->parse_protoinfo(tb, ct);
}

static void nfct_parse_counters(struct nfattr *attr,
					struct nfct_conntrack *ct,
					enum ctattr_type parent)
{
	struct nfattr *tb[CTA_COUNTERS_MAX];
	int dir = (parent == CTA_COUNTERS_ORIG ? NFCT_DIR_REPLY 
					       : NFCT_DIR_ORIGINAL);

	nfnl_parse_nested(tb, CTA_COUNTERS_MAX, attr);
	if (tb[CTA_COUNTERS_PACKETS-1])
		ct->counters[dir].packets
			= __be64_to_cpu(*(u_int64_t *)
					NFA_DATA(tb[CTA_COUNTERS_PACKETS-1]));
	if (tb[CTA_COUNTERS_BYTES-1])
		ct->counters[dir].bytes
			= __be64_to_cpu(*(u_int64_t *)
					NFA_DATA(tb[CTA_COUNTERS_BYTES-1]));
	if (tb[CTA_COUNTERS32_PACKETS-1])
		ct->counters[dir].packets
			= ntohl(*(u_int32_t *)
				NFA_DATA(tb[CTA_COUNTERS32_PACKETS-1]));
	if (tb[CTA_COUNTERS32_BYTES-1])
		ct->counters[dir].bytes
			= ntohl(*(u_int32_t *)
				NFA_DATA(tb[CTA_COUNTERS32_BYTES-1]));
}

static char *msgtype[] = {"[UNKNOWN]", "[NEW]", "[UPDATE]", "[DESTROY]"};

static int typemsg2enum(u_int16_t type, u_int16_t flags)
{
	int ret = NFCT_MSG_UNKNOWN;

	if (type == IPCTNL_MSG_CT_NEW) {
		if (flags & (NLM_F_CREATE|NLM_F_EXCL))
			ret = NFCT_MSG_NEW;
		else
			ret = NFCT_MSG_UPDATE;
	} else if (type == IPCTNL_MSG_CT_DELETE)
		ret = NFCT_MSG_DESTROY;

	return ret;
}

static int nfct_conntrack_netlink_handler(struct nfct_handle *cth, 
					  struct nlmsghdr *nlh, void *arg)
{
	struct nfct_conntrack ct;
	unsigned int flags = 0;
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type), ret = 0;
	int len = nlh->nlmsg_len;
	struct nfattr *cda[CTA_MAX];

	len -= NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0)
		return -EINVAL;

	memset(&ct, 0, sizeof(struct nfct_conntrack));

	ct.tuple[NFCT_DIR_ORIGINAL].l3protonum = nfhdr->nfgen_family;
	ct.tuple[NFCT_DIR_REPLY].l3protonum = nfhdr->nfgen_family;

	nfnl_parse_attr(cda, CTA_MAX, NFA_DATA(nfhdr), len);

	if (cda[CTA_TUPLE_ORIG-1])
		parse_tuple(cda[CTA_TUPLE_ORIG-1], 
			    &ct.tuple[NFCT_DIR_ORIGINAL]);
	
	if (cda[CTA_TUPLE_REPLY-1])
		parse_tuple(cda[CTA_TUPLE_REPLY-1], 
			    &ct.tuple[NFCT_DIR_REPLY]);
	
	if (cda[CTA_STATUS-1]) {
		ct.status = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_STATUS-1]));
		flags |= NFCT_STATUS;
	}

	if (cda[CTA_PROTOINFO-1]) {
		parse_protoinfo(cda[CTA_PROTOINFO-1], &ct);
		flags |= NFCT_PROTOINFO;
	}

	if (cda[CTA_TIMEOUT-1]) {
		ct.timeout = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_TIMEOUT-1]));
		flags |= NFCT_TIMEOUT;
	}
	
	if (cda[CTA_MARK-1]) {
		ct.mark = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_MARK-1]));
		flags |= NFCT_MARK;
	}
	
	if (cda[CTA_COUNTERS_ORIG-1]) {
		nfct_parse_counters(cda[CTA_COUNTERS_ORIG-1], &ct, 
				    NFA_TYPE(cda[CTA_COUNTERS_ORIG-1])-1);
		flags |= NFCT_COUNTERS_ORIG;
	}

	if (cda[CTA_COUNTERS_REPLY-1]) {
		nfct_parse_counters(cda[CTA_COUNTERS_REPLY-1], &ct, 
				    NFA_TYPE(cda[CTA_COUNTERS_REPLY-1])-1);
		flags |= NFCT_COUNTERS_RPLY;
	}

	if (cda[CTA_USE-1]) {
		ct.use = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_USE-1]));
		flags |= NFCT_USE;
	}

	if (cda[CTA_ID-1]) {
		ct.id = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_ID-1]));
		flags |= NFCT_ID;
	}

	if (cth->callback)
		ret = cth->callback((void *) &ct, flags,
				    typemsg2enum(type, nlh->nlmsg_flags),
				    cth->callback_data);

	return ret;
}

int nfct_sprintf_protocol(char *buf, struct nfct_conntrack *ct)
{
	return (sprintf(buf, "%-8s %u ", 
		proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum] == NULL ?
		"unknown" : proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum], 
		 ct->tuple[NFCT_DIR_ORIGINAL].protonum));
}

int nfct_sprintf_timeout(char *buf, struct nfct_conntrack *ct)
{
	return sprintf(buf, "%u ", ct->timeout);
}

int nfct_sprintf_protoinfo(char *buf, struct nfct_conntrack *ct)
{
	int size = 0;
	struct nfct_proto *h = NULL;
	
	h = findproto(proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum]);
	if (h && h->print_protoinfo)
		size += h->print_protoinfo(buf+size, &ct->protoinfo);
	
	return size;
}

int nfct_sprintf_address(char *buf, struct nfct_tuple *t)
{
	int size = 0;
	struct nfct_l3proto *h;

	h = findl3proto(l3proto2str[t->l3protonum]);
	if (h && h->print_proto)
		size += h->print_proto(buf, t);

	return size;
}

int nfct_sprintf_proto(char *buf, struct nfct_tuple *t)
{
	int size = 0;
	struct nfct_proto *h = NULL;

	h = findproto(proto2str[t->protonum]);
	if (h && h->print_proto)
		size += h->print_proto(buf, t);

	return size;
}

int nfct_sprintf_counters(char *buf, struct nfct_conntrack *ct, int dir)
{
	return (sprintf(buf, "packets=%llu bytes=%llu ",
			(unsigned long long) ct->counters[dir].packets,
			(unsigned long long) ct->counters[dir].bytes));
}

int nfct_sprintf_mark(char *buf, struct nfct_conntrack *ct)
{
	return (sprintf(buf, "mark=%u ", ct->mark));
}

int nfct_sprintf_use(char *buf, struct nfct_conntrack *ct)
{
	return (sprintf(buf, "use=%u ", ct->use));
}

int nfct_sprintf_id(char *buf, u_int32_t id)
{
	return (sprintf(buf, "id=%u ", id));
}

int nfct_sprintf_conntrack(char *buf, struct nfct_conntrack *ct, 
			  unsigned int flags)
{
	int size = 0;

	size += nfct_sprintf_protocol(buf, ct);

	if (flags & NFCT_TIMEOUT)
		size += nfct_sprintf_timeout(buf+size, ct);

        if (flags & NFCT_PROTOINFO)
		size += nfct_sprintf_protoinfo(buf+size, ct);

	size += nfct_sprintf_address(buf+size, &ct->tuple[NFCT_DIR_ORIGINAL]);
	size += nfct_sprintf_proto(buf+size, &ct->tuple[NFCT_DIR_ORIGINAL]);

	if (flags & NFCT_COUNTERS_ORIG)
		size += nfct_sprintf_counters(buf+size, ct, NFCT_DIR_ORIGINAL);

	if (flags & NFCT_STATUS)
		size += nfct_sprintf_status_seen_reply(buf+size, ct);

	size += nfct_sprintf_address(buf+size, &ct->tuple[NFCT_DIR_REPLY]);
	size += nfct_sprintf_proto(buf+size, &ct->tuple[NFCT_DIR_REPLY]);

	if (flags & NFCT_COUNTERS_RPLY)
		size += nfct_sprintf_counters(buf+size, ct, NFCT_DIR_REPLY);
	
	if (flags & NFCT_STATUS)
		size += nfct_sprintf_status_assured(buf+size, ct);

	if (flags & NFCT_MARK)
		size += nfct_sprintf_mark(buf+size, ct);

	if (flags & NFCT_USE)
		size += nfct_sprintf_use(buf+size, ct);

	/* Delete the last blank space */
	size--;

	return size;
}

int nfct_sprintf_conntrack_id(char *buf, struct nfct_conntrack *ct, 
			     unsigned int flags)
{
	int size;
	
	/* add a blank space, that's why the add 1 to the size */
	size = nfct_sprintf_conntrack(buf, ct, flags) + 1;
	if (flags & NFCT_ID)
		size += nfct_sprintf_id(buf+size, ct->id);

	/* Delete the last blank space */
	return --size;
}

int nfct_default_conntrack_display(void *arg, unsigned int flags, int type,
				   void *data)
{
	char buf[512];
	int size;
	struct nfct_conntrack_compare *cmp = data;

	if (cmp && !nfct_conntrack_compare(cmp->ct, arg, cmp))
		return 0;

	memset(buf, 0, sizeof(buf));
	size = nfct_sprintf_conntrack(buf, arg, flags);
	sprintf(buf+size, "\n");
	fprintf(stdout, buf);

	return 0;
}

int nfct_default_conntrack_display_id(void *arg, unsigned int flags, int type,
				      void *data)
{
	char buf[512];
	int size;
        struct nfct_conntrack_compare *cmp = data;

	if (cmp && !nfct_conntrack_compare(cmp->ct, arg, cmp))
		return 0;

	memset(buf, 0, sizeof(buf));
	size = nfct_sprintf_conntrack_id(buf, arg, flags);
	sprintf(buf+size, "\n");
	fprintf(stdout, buf);

	return 0;
}

int nfct_default_conntrack_event_display(void *arg, unsigned int flags, 
					 int type, void *data)
{
	char buf[512];
	int size;
	struct nfct_conntrack_compare *cmp = data;

	if (cmp && !nfct_conntrack_compare(cmp->ct, arg, cmp))
		return 0;

	memset(buf, 0, sizeof(buf));
	size = sprintf(buf, "%9s ", msgtype[type]);
	size += nfct_sprintf_conntrack_id(buf + size, arg, flags);
	sprintf(buf+size, "\n");
	fprintf(stdout, buf);
	fflush(stdout);

	return 0;
}

int nfct_sprintf_expect_proto(char *buf, struct nfct_expect *exp)
{
	 return(sprintf(buf, "%u proto=%d ", exp->timeout, 
					     exp->tuple.protonum));
}

int nfct_sprintf_expect(char *buf, struct nfct_expect *exp)
{
	int size = 0;
	
	size = nfct_sprintf_expect_proto(buf, exp);
	size += nfct_sprintf_address(buf+size, &exp->tuple);
	size += nfct_sprintf_proto(buf+size, &exp->tuple);

	/* remove last blank space */
	return --size;
}

int nfct_sprintf_expect_id(char *buf, struct nfct_expect *exp)
{
	int size = 0;

	/* add a blank space, that's why the add 1 to the size */
	size = nfct_sprintf_expect(buf, exp) + 1;
	size += nfct_sprintf_id(buf+size, exp->id);

	/* remove last blank space */
	return --size;
}

int nfct_default_expect_display(void *arg, unsigned int flags, int type,
				void *data)
{
	char buf[256];
	int size = 0;

	memset(buf, 0, sizeof(buf));
	size = nfct_sprintf_expect(buf, arg);
	sprintf(buf+size, "\n");
	fprintf(stdout, buf);

	return 0;
}

int nfct_default_expect_display_id(void *arg, unsigned int flags, int type,
				   void *data)
{
	char buf[256];
	int size = 0;

	size = nfct_sprintf_expect_id(buf, arg);
	sprintf(buf+size, "\n");
	fprintf(stdout, buf);

	return 0;
}

static int nfct_expect_netlink_handler(struct nfct_handle *cth, 
				       struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	struct nfct_expect exp;
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type), ret = 0;
	int len = nlh->nlmsg_len;
	struct nfattr *cda[CTA_EXPECT_MAX];

	len -= NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0)
		return -EINVAL;
	
	memset(&exp, 0, sizeof(struct nfct_expect));

	exp.tuple.l3protonum = nfhdr->nfgen_family;

	nfnl_parse_attr(cda, CTA_EXPECT_MAX, NFA_DATA(nfhdr), len);

	if (cda[CTA_EXPECT_TUPLE-1])
		parse_tuple(cda[CTA_EXPECT_TUPLE-1], &exp.tuple);

	if (cda[CTA_EXPECT_MASK-1])
		parse_mask(cda[CTA_EXPECT_MASK-1], &exp.mask, 
			   exp.tuple.l3protonum, exp.tuple.protonum);

	if (cda[CTA_EXPECT_TIMEOUT-1])
		exp.timeout = ntohl(*(u_int32_t *)
				NFA_DATA(cda[CTA_EXPECT_TIMEOUT-1]));

	if (cda[CTA_EXPECT_ID-1])
		exp.id = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_EXPECT_ID-1]));

	if (cth->callback)
		ret = cth->callback((void *)&exp, 0, 
				    typemsg2enum(type, nlh->nlmsg_flags),
				    cth->callback_data);

	return 0;
}

struct nfct_conntrack *
nfct_conntrack_alloc(struct nfct_tuple *orig, struct nfct_tuple *reply,
		     u_int32_t timeout, union nfct_protoinfo *proto,
		     u_int32_t status, u_int32_t mark, 
		     u_int32_t id, struct nfct_nat *range)
{
	struct nfct_conntrack *ct;

	ct = malloc(sizeof(struct nfct_conntrack));
	if (!ct)
		return NULL;
	memset(ct, 0, sizeof(struct nfct_conntrack));

	ct->tuple[NFCT_DIR_ORIGINAL] = *orig;
	ct->tuple[NFCT_DIR_REPLY] = *reply;
	ct->timeout = timeout;
	ct->status = status;
	ct->protoinfo = *proto;
	ct->mark = mark;
	if (id != NFCT_ANY_ID)
		ct->id = id;
	if (range)
		ct->nat = *range;

	return ct;
}

void nfct_conntrack_free(struct nfct_conntrack *ct)
{
	free(ct);
}

#define L3PROTONUM(ct) ct->tuple[NFCT_DIR_ORIGINAL].l3protonum
#define L4PROTONUM(ct) ct->tuple[NFCT_DIR_ORIGINAL].protonum

int nfct_conntrack_compare(struct nfct_conntrack *ct1,
			   struct nfct_conntrack *ct2,
			   struct nfct_conntrack_compare *cmp)
{
	struct nfct_l3proto *l3proto;
	struct nfct_proto *proto;
	unsigned int l3flags = cmp->l3flags;
	unsigned int l4flags = cmp->l4flags;
	unsigned int flags = cmp->flags;

	if ((flags & NFCT_MARK) && (ct1->mark != ct2->mark))
		return 0;

	if (l3flags) {
		if (ct1->tuple[NFCT_DIR_ORIGINAL].l3protonum != AF_UNSPEC && 
		    ct2->tuple[NFCT_DIR_ORIGINAL].l3protonum != AF_UNSPEC &&
		    ct1->tuple[NFCT_DIR_ORIGINAL].l3protonum !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].l3protonum)
				return 0;
		if (ct1->tuple[NFCT_DIR_REPLY].l3protonum != AF_UNSPEC && 
		    ct2->tuple[NFCT_DIR_REPLY].l3protonum != AF_UNSPEC &&
		    ct1->tuple[NFCT_DIR_REPLY].l3protonum !=
		    ct2->tuple[NFCT_DIR_REPLY].l3protonum)
				return 0;
		l3proto = findl3proto(l3proto2str[L3PROTONUM(ct1)]);
		if (l3proto && !l3proto->compare(ct1, ct2, l3flags))
			return 0;
	}

	if (l4flags) {
		if (ct1->tuple[NFCT_DIR_ORIGINAL].protonum != 0 && 
		    ct2->tuple[NFCT_DIR_ORIGINAL].protonum != 0 &&
		    ct1->tuple[NFCT_DIR_ORIGINAL].protonum !=
		    ct2->tuple[NFCT_DIR_ORIGINAL].protonum)
				return 0;
		if (ct1->tuple[NFCT_DIR_REPLY].protonum != 0 && 
		    ct2->tuple[NFCT_DIR_REPLY].protonum != 0 &&
		    ct1->tuple[NFCT_DIR_REPLY].protonum !=
		    ct2->tuple[NFCT_DIR_REPLY].protonum)
				return 0;
		proto = findproto(proto2str[L4PROTONUM(ct1)]);
		if (proto && !proto->compare(ct1, ct2, l4flags))
			return 0;
	}

	return 1;
}

int nfct_create_conntrack(struct nfct_handle *cth, struct nfct_conntrack *ct)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	u_int32_t status = htonl(ct->status | IPS_CONFIRMED);
	u_int32_t timeout = htonl(ct->timeout);
	u_int32_t mark = htonl(ct->mark);
	u_int8_t l3num = ct->tuple[NFCT_DIR_ORIGINAL].l3protonum;

	req = (void *) buf;

	memset(buf, 0, sizeof(buf));
	
	nfnl_fill_hdr(cth->nfnlssh_ct, &req->nlh, 0, l3num, 0, 
		      IPCTNL_MSG_CT_NEW,
		      NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL);

	nfct_build_tuple(req, sizeof(buf), &ct->tuple[NFCT_DIR_ORIGINAL], 
				 CTA_TUPLE_ORIG);
	nfct_build_tuple(req, sizeof(buf), &ct->tuple[NFCT_DIR_REPLY],
				 CTA_TUPLE_REPLY);

	nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_STATUS, &status, 
		       sizeof(u_int32_t));

	nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_TIMEOUT, &timeout, 
		       sizeof(u_int32_t));
	
	if (ct->mark != 0)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_MARK, &mark,
			       sizeof(u_int32_t));

	nfct_build_protoinfo(req, sizeof(buf), ct);
	if (ct->nat.min_ip != 0)
		nfct_build_nat(req, sizeof(buf), ct);

	return nfnl_talk(cth->nfnlh, &req->nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_update_conntrack(struct nfct_handle *cth, struct nfct_conntrack *ct)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	u_int32_t status = htonl(ct->status | IPS_CONFIRMED);
	u_int32_t timeout = htonl(ct->timeout);
	u_int32_t id = htonl(ct->id);
	u_int32_t mark = htonl(ct->mark);
	u_int8_t l3num = ct->tuple[NFCT_DIR_ORIGINAL].l3protonum;

	req = (void *) &buf;
	memset(&buf, 0, sizeof(buf));

	nfnl_fill_hdr(cth->nfnlssh_ct, &req->nlh, 0, l3num, 0, 
		      IPCTNL_MSG_CT_NEW, NLM_F_REQUEST|NLM_F_ACK);	

	nfct_build_tuple(req, sizeof(buf), &ct->tuple[NFCT_DIR_ORIGINAL], 
				 CTA_TUPLE_ORIG);
	nfct_build_tuple(req, sizeof(buf), &ct->tuple[NFCT_DIR_REPLY],
				 CTA_TUPLE_REPLY);

	if (ct->status != 0)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_STATUS, &status, 
			       sizeof(u_int32_t));

	if (ct->timeout != 0)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_TIMEOUT, &timeout, 
			       sizeof(u_int32_t));
	
	if (ct->mark != 0)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_MARK, &mark,
			       sizeof(u_int32_t));

	if (ct->id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_ID, &id, 
			       sizeof(u_int32_t));

	nfct_build_protoinfo(req, sizeof(buf), ct);

	return nfnl_talk(cth->nfnlh, &req->nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_delete_conntrack(struct nfct_handle *cth, struct nfct_tuple *tuple, 
			  int dir, u_int32_t id)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	int type = dir ? CTA_TUPLE_REPLY : CTA_TUPLE_ORIG;
	 u_int8_t l3num = tuple->l3protonum;

	req = (void *) &buf;
	memset(&buf, 0, sizeof(buf));

	nfnl_fill_hdr(cth->nfnlssh_ct, &req->nlh, 0, 
		      l3num, 0, IPCTNL_MSG_CT_DELETE, 
		      NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK);

	nfct_build_tuple(req, sizeof(buf), tuple, type);

	if (id != NFCT_ANY_ID) {
		id = htonl(id); /* to network byte order */
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_ID, &id, 
			       sizeof(u_int32_t));
	}

	return nfnl_talk(cth->nfnlh, &req->nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_get_conntrack(struct nfct_handle *cth, struct nfct_tuple *tuple, 
		       int dir, u_int32_t id)
{
	int err;
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	int type = dir ? CTA_TUPLE_REPLY : CTA_TUPLE_ORIG;
	u_int8_t l3num = tuple->l3protonum;

	cth->handler = nfct_conntrack_netlink_handler;
	
	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(cth->nfnlssh_ct, &req->nlh, 0,
		      l3num, 0, IPCTNL_MSG_CT_GET,
		      NLM_F_REQUEST|NLM_F_ACK);
	
	nfct_build_tuple(req, sizeof(buf), tuple, type);

        if (id != NFCT_ANY_ID) {
		id = htonl(id); /* to network byte order */
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_ID, &id,
			       sizeof(u_int32_t));
	}

	err = nfnl_send(cth->nfnlh, &req->nlh);
	if (err < 0)
		return err;

	return nfnl_listen(cth->nfnlh, &callback_handler, cth);
}

static int __nfct_dump_conntrack_table(struct nfct_handle *cth, int zero, 
				       int family)
{
	int err, msg;
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));
	cth->handler = nfct_conntrack_netlink_handler;

	if (zero)
		msg = IPCTNL_MSG_CT_GET_CTRZERO;
	else
		msg = IPCTNL_MSG_CT_GET;

	nfnl_fill_hdr(cth->nfnlssh_ct, &req.nlh, 0, family, 0,
		      msg, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_DUMP);

	err = nfnl_send(cth->nfnlh, &req.nlh);
	if (err < 0)
		return err;

	return nfnl_listen(cth->nfnlh, &callback_handler, cth); 
}

int nfct_dump_conntrack_table(struct nfct_handle *cth, int family)
{
	return(__nfct_dump_conntrack_table(cth, 0, family));
}

int nfct_dump_conntrack_table_reset_counters(struct nfct_handle *cth,
					     int family)
{
	return(__nfct_dump_conntrack_table(cth, 1, family));
}

int nfct_event_conntrack(struct nfct_handle *cth)
{
	cth->handler = nfct_conntrack_netlink_handler;
	return nfnl_listen(cth->nfnlh, &callback_handler, cth);
}

void nfct_register_proto(struct nfct_proto *h)
{
	if (strcmp(h->version, VERSION) != 0) {
		fprintf(stderr, "plugin `%s': version %s (I'm %s)\n",
			h->name, h->version, VERSION);
		exit(1);
	}
	list_add(&h->head, &proto_list);
}

void nfct_register_l3proto(struct nfct_l3proto *h)
{
	if (strcmp(h->version, VERSION) != 0) {
		fprintf(stderr, "plugin `%s': version %s (I'm %s)\n",
			h->name, h->version, VERSION);
		exit(1);
	}
	list_add(&h->head, &l3proto_list);
}

int nfct_dump_expect_list(struct nfct_handle *cth, int family)
{
	int err;
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));

	cth->handler = nfct_expect_netlink_handler;
	nfnl_fill_hdr(cth->nfnlssh_exp, &req.nlh, 0, family, 0,
		      IPCTNL_MSG_EXP_GET, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST);

	err = nfnl_send(cth->nfnlh, &req.nlh);
	if (err < 0)
		return err;

	return nfnl_listen(cth->nfnlh, &callback_handler, cth);
}

int nfct_flush_conntrack_table(struct nfct_handle *cth, int family)
{
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));

	nfnl_fill_hdr(cth->nfnlssh_ct, (struct nlmsghdr *) &req,
			0, family, 0, IPCTNL_MSG_CT_DELETE,
			NLM_F_REQUEST|NLM_F_ACK);

	return nfnl_talk(cth->nfnlh, &req.nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_get_expectation(struct nfct_handle *cth, struct nfct_tuple *tuple,
			 u_int32_t id)
{
	int err;
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	u_int8_t l3num = tuple->l3protonum;

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(cth->nfnlssh_exp, &req->nlh, 0, l3num, 0,
		      IPCTNL_MSG_EXP_GET,
		      NLM_F_REQUEST|NLM_F_ACK);

	cth->handler = nfct_expect_netlink_handler;
	nfct_build_tuple(req, sizeof(buf), tuple, CTA_EXPECT_MASTER);

	if (id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_EXPECT_ID, &id,
			       sizeof(u_int32_t));

	err = nfnl_send(cth->nfnlh, &req->nlh);
	if (err < 0)
		return err;

	return nfnl_listen(cth->nfnlh, &callback_handler, cth);
}

struct nfct_expect *
nfct_expect_alloc(struct nfct_tuple *master, struct nfct_tuple *tuple,
		  struct nfct_tuple *mask, u_int32_t timeout, 
		  u_int32_t id)
{
	struct nfct_expect *exp;

	exp = malloc(sizeof(struct nfct_expect));
	if (!exp)
		return NULL;
	memset(exp, 0, sizeof(struct nfct_expect));

	exp->master = *master;
	exp->tuple = *tuple;
	exp->mask = *mask;
	exp->timeout = timeout;
	if (id != NFCT_ANY_ID)
		exp->id = htonl(id);

	return exp;
}

void nfct_expect_free(struct nfct_expect *exp)
{
	free(exp);
}

int nfct_create_expectation(struct nfct_handle *cth, struct nfct_expect *exp)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	req = (void *) &buf;
	u_int8_t l3num = exp->tuple.l3protonum;
	u_int32_t timeout;
	u_int16_t queuenr;

	memset(&buf, 0, sizeof(buf));

	nfnl_fill_hdr(cth->nfnlssh_exp, &req->nlh, 0, l3num, 0,
		      IPCTNL_MSG_EXP_NEW,
		      NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK);

	nfct_build_tuple(req, sizeof(buf), &exp->master, CTA_EXPECT_MASTER);
	nfct_build_tuple(req, sizeof(buf), &exp->tuple, CTA_EXPECT_TUPLE);
	nfct_build_tuple(req, sizeof(buf), &exp->mask, CTA_EXPECT_MASK);
	
	timeout = htonl(exp->timeout);
	nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_EXPECT_TIMEOUT, 
		       &timeout, sizeof(u_int32_t));

	queuenr = htons(exp->expectfn_queue_id);
	if (queuenr)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_EXPECT_QUEUENR,
			       &queuenr, sizeof(u_int16_t));

	return nfnl_talk(cth->nfnlh, &req->nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_delete_expectation(struct nfct_handle *cth, struct nfct_tuple *tuple,
			    u_int32_t id)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	u_int8_t l3num = tuple->l3protonum;

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;
	
	nfnl_fill_hdr(cth->nfnlssh_exp, &req->nlh, 0, l3num, 
		      0, IPCTNL_MSG_EXP_DELETE,
		      NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK);

	nfct_build_tuple(req, sizeof(buf), tuple, CTA_EXPECT_MASTER);

	if (id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_EXPECT_ID, &id,
			       sizeof(u_int32_t));

	return nfnl_talk(cth->nfnlh, &req->nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_event_expectation(struct nfct_handle *cth)
{
	cth->handler = nfct_expect_netlink_handler;
	return nfnl_listen(cth->nfnlh, &callback_handler, cth);
}

int nfct_flush_expectation_table(struct nfct_handle *cth, int family)
{
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));
	
	nfnl_fill_hdr(cth->nfnlssh_exp, (struct nlmsghdr *) &req,
		      0, family, 0, IPCTNL_MSG_EXP_DELETE,
		      NLM_F_REQUEST|NLM_F_ACK);

	return nfnl_talk(cth->nfnlh, &req.nlh, 0, 0, NULL, NULL, NULL);
}
