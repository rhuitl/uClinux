/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

static void __build_timeout(struct nfnlhdr *req,
			    size_t size,
			    const struct nf_expect *exp)
{
	nfnl_addattr32(&req->nlh, size, CTA_EXPECT_TIMEOUT,htonl(exp->timeout));
}

int __build_expect(struct nfnl_subsys_handle *ssh,
		   struct nfnlhdr *req,
		   size_t size,
		   u_int16_t type,
		   u_int16_t flags,
		   const struct nf_expect *exp)
{
	u_int8_t l3num;

	if (test_bit(ATTR_ORIG_L3PROTO, exp->master.set))
		l3num = exp->master.tuple[NFCT_DIR_ORIGINAL].l3protonum;
	else if (test_bit(ATTR_ORIG_L3PROTO, exp->expected.set))
		l3num = exp->expected.tuple[NFCT_DIR_ORIGINAL].l3protonum;

	memset(req, 0, size);

	nfnl_fill_hdr(ssh, &req->nlh, 0, l3num, 0, type, flags);

	if (test_bit(ATTR_EXP_EXPECTED, exp->set)) {
		__build_tuple(req,
			      size,
			      &exp->expected.tuple[__DIR_ORIG],
			      CTA_EXPECT_TUPLE);
	}

	if (test_bit(ATTR_EXP_MASTER, exp->set)) {
		__build_tuple(req,
			      size,
			      &exp->master.tuple[__DIR_ORIG],
			      CTA_EXPECT_MASTER);
	}

	if (test_bit(ATTR_EXP_MASK, exp->set)) {
		__build_tuple(req,
			      size,
			      &exp->mask.tuple[__DIR_ORIG],
			      CTA_EXPECT_MASK);
	}

	if (test_bit(ATTR_EXP_TIMEOUT, exp->set))
		__build_timeout(req, size, exp);

	return 0;
}
