/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

void __build_tuple_ip(struct nfnlhdr *req, 
		      size_t size,
		      const struct __nfct_tuple *t)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_TUPLE_IP);

	switch(t->l3protonum) {
	case AF_INET:
	        nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_SRC, &t->src.v4,
			       sizeof(u_int32_t));
		nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_DST, &t->dst.v4,
			       sizeof(u_int32_t));
		break;
	case AF_INET6:
		nfnl_addattr_l(&req->nlh, size, CTA_IP_V6_SRC, &t->src.v6,
			       sizeof(struct in6_addr));
		nfnl_addattr_l(&req->nlh, size, CTA_IP_V6_DST, &t->dst.v6,
			       sizeof(struct in6_addr));
		break;
	default:
		break;
	}

	nfnl_nest_end(&req->nlh, nest);
}

void __build_tuple_proto(struct nfnlhdr *req,
			 size_t size,
			 const struct __nfct_tuple *t)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_TUPLE_PROTO);

	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_NUM, &t->protonum,
		       sizeof(u_int8_t));

	switch(t->protonum) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_SRC_PORT,
			       &t->l4src.tcp.port, sizeof(u_int16_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_DST_PORT,
			       &t->l4dst.tcp.port, sizeof(u_int16_t));
		break;
	case IPPROTO_ICMP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_CODE,
			       &t->l4dst.icmp.code, sizeof(u_int8_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_TYPE,
			       &t->l4dst.icmp.type, sizeof(u_int8_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_ID,
			       &t->l4src.icmp.id, sizeof(u_int16_t));
		break;
	default:
		break;
	}

	nfnl_nest_end(&req->nlh, nest);
}

void __build_tuple(struct nfnlhdr *req, 
		   size_t size, 
		   const struct __nfct_tuple *t, 
		   const int type)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, type);

	__build_tuple_ip(req, size, t);
	__build_tuple_proto(req, size, t);

	nfnl_nest_end(&req->nlh, nest);
}

void __build_protoinfo(struct nfnlhdr *req,
		       size_t size,
		       const struct nf_conntrack *ct)
{
	struct nfattr *nest, *nest_proto;

	switch(ct->tuple[__DIR_ORIG].protonum) {
	case IPPROTO_TCP:
		nest = nfnl_nest(&req->nlh, size, CTA_PROTOINFO);
		nest_proto = nfnl_nest(&req->nlh, size, CTA_PROTOINFO_TCP);
		nfnl_addattr_l(&req->nlh, size, CTA_PROTOINFO_TCP_STATE,
			       &ct->protoinfo.tcp.state, sizeof(u_int8_t));
		nfnl_nest_end(&req->nlh, nest_proto);
		nfnl_nest_end(&req->nlh, nest);
		break;
	default:
		break;
	}
}

void __build_protonat(struct nfnlhdr *req,
		      size_t size,
		      const struct nf_conntrack *ct,
		      const struct __nfct_nat *nat)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_PROTO);

	switch (ct->tuple[NFCT_DIR_ORIGINAL].protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_PORT_MIN,
			       &nat->l4min.tcp.port, sizeof(u_int16_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_PORT_MAX,
			       &nat->l4max.tcp.port, sizeof(u_int16_t));
		break;
	}
	nfnl_nest_end(&req->nlh, nest);
}

void __build_nat(struct nfnlhdr *req,
		 size_t size,
		 const struct __nfct_nat *nat)
{
	nfnl_addattr_l(&req->nlh, size, CTA_NAT_MINIP,
		       &nat->min_ip, sizeof(u_int32_t));
}

void __build_snat(struct nfnlhdr *req,
		  size_t size,
		  const struct nf_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_SRC);
	__build_nat(req, size, &ct->snat);
	__build_protonat(req, size, ct, &ct->snat);
	nfnl_nest_end(&req->nlh, nest);
}

void __build_snat_ipv4(struct nfnlhdr *req,
		       size_t size,
		       const struct nf_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_SRC);
	__build_nat(req, size, &ct->snat);
	nfnl_nest_end(&req->nlh, nest);
}

void __build_snat_port(struct nfnlhdr *req,
		       size_t size,
		       const struct nf_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_SRC);
	__build_protonat(req, size, ct, &ct->snat);
	nfnl_nest_end(&req->nlh, nest);
}

void __build_dnat(struct nfnlhdr *req,
		  size_t size, 
		  const struct nf_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_DST);
	__build_nat(req, size, &ct->dnat);
	__build_protonat(req, size, ct, &ct->dnat);
	nfnl_nest_end(&req->nlh, nest);
}

void __build_dnat_ipv4(struct nfnlhdr *req,
		       size_t size, 
		       const struct nf_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_DST);
	__build_nat(req, size, &ct->dnat);
	nfnl_nest_end(&req->nlh, nest);
}

void __build_dnat_port(struct nfnlhdr *req,
		       size_t size, 
		       const struct nf_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_DST);
        __build_protonat(req, size, ct, &ct->dnat);
	nfnl_nest_end(&req->nlh, nest);
}

void __build_status(struct nfnlhdr *req,
		    size_t size,
		    const struct nf_conntrack *ct)
{
	nfnl_addattr32(&req->nlh, size, CTA_STATUS,
		       htonl(ct->status | IPS_CONFIRMED));
}

void __build_timeout(struct nfnlhdr *req,
			size_t size,
			const struct nf_conntrack *ct)
{
	nfnl_addattr32(&req->nlh, size, CTA_TIMEOUT, htonl(ct->timeout));
}

void __build_mark(struct nfnlhdr *req,
		  size_t size,
		  const struct nf_conntrack *ct)
{
	nfnl_addattr32(&req->nlh, size, CTA_MARK, htonl(ct->mark));
}

int __build_conntrack(struct nfnl_subsys_handle *ssh,
		      struct nfnlhdr *req,
		      size_t size,
		      u_int16_t type,
		      u_int16_t flags,
		      const struct nf_conntrack *ct)
{
	u_int8_t l3num = ct->tuple[NFCT_DIR_ORIGINAL].l3protonum;

	if (!test_bit(ATTR_ORIG_L3PROTO, ct->set)) {
		errno = EINVAL;
		return -1;
	}

	memset(req, 0, size);

	nfnl_fill_hdr(ssh, &req->nlh, 0, l3num, 0, type, flags);

	__build_tuple(req, size, &ct->tuple[__DIR_ORIG], CTA_TUPLE_ORIG);
	__build_tuple(req, size, &ct->tuple[__DIR_REPL], CTA_TUPLE_REPLY);

	if (test_bit(ATTR_STATUS, ct->set))
		__build_status(req, size, ct);
	else {
		/* build IPS_CONFIRMED if we're creating a new conntrack */
		if (type == IPCTNL_MSG_CT_NEW && flags & NLM_F_CREATE)
			__build_status(req, size, ct);
	}

	if (test_bit(ATTR_TIMEOUT, ct->set))
		__build_timeout(req, size, ct);

	if (test_bit(ATTR_MARK, ct->set))
		__build_mark(req, size, ct);

	if (test_bit(ATTR_TCP_STATE, ct->set))
		__build_protoinfo(req, size, ct);

	if (test_bit(ATTR_SNAT_IPV4, ct->set) && 
	    test_bit(ATTR_SNAT_PORT, ct->set))
		__build_snat(req, size, ct);
	else if (test_bit(ATTR_SNAT_IPV4, ct->set))
		__build_snat_ipv4(req, size, ct);
	else if (test_bit(ATTR_SNAT_PORT, ct->set))
		__build_snat_port(req, size, ct);

	if (test_bit(ATTR_DNAT_IPV4, ct->set) &&
	    test_bit(ATTR_DNAT_PORT, ct->set))
		__build_dnat(req, size, ct);
	else if (test_bit(ATTR_DNAT_IPV4, ct->set))
		__build_dnat_ipv4(req, size, ct);
	else if (test_bit(ATTR_DNAT_PORT, ct->set))
		__build_dnat_port(req, size, ct);

	return 0;
}
