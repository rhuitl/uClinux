/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

static int __autocomplete(struct nf_conntrack *ct, int dir)
{
	int other = (dir == __DIR_ORIG) ? __DIR_REPL : __DIR_ORIG;

	ct->tuple[dir].l3protonum = ct->tuple[other].l3protonum;
	ct->tuple[dir].protonum = ct->tuple[other].protonum;

	memcpy(&ct->tuple[dir].src.v6, 
	       &ct->tuple[other].dst.v6,
	       sizeof(union __nfct_address));
	memcpy(&ct->tuple[dir].dst.v6, 
	       &ct->tuple[other].src.v6,
	       sizeof(union __nfct_address));

	ct->tuple[dir].l4src.all = ct->tuple[other].l4dst.all;
	ct->tuple[dir].l4dst.all = ct->tuple[other].l4src.all;
}

int __setobjopt(struct nf_conntrack *ct, unsigned int option)
{
	switch(option) {
	case NFCT_SOPT_UNDO_SNAT:
		ct->snat.min_ip = ct->tuple[__DIR_REPL].dst.v4;
		ct->snat.max_ip = ct->snat.min_ip;
		ct->tuple[__DIR_REPL].dst.v4 = ct->tuple[__DIR_ORIG].src.v4;
		set_bit(ATTR_SNAT_IPV4, ct->set);
		break;
	case NFCT_SOPT_UNDO_DNAT:
		ct->dnat.min_ip = ct->tuple[__DIR_REPL].src.v4;
		ct->dnat.max_ip = ct->dnat.min_ip;
		ct->tuple[__DIR_REPL].src.v4 = ct->tuple[__DIR_ORIG].dst.v4;
		set_bit(ATTR_DNAT_IPV4, ct->set);
		break;
	case NFCT_SOPT_UNDO_SPAT:
		ct->snat.l4min.all = ct->tuple[__DIR_REPL].l4dst.tcp.port;
		ct->snat.l4max.all = ct->snat.l4max.all;
		ct->tuple[__DIR_REPL].l4dst.tcp.port = 
			ct->tuple[__DIR_ORIG].l4src.tcp.port;
		set_bit(ATTR_SNAT_PORT, ct->set);
		break;
	case NFCT_SOPT_UNDO_DPAT:
		ct->dnat.l4min.all = ct->tuple[__DIR_REPL].l4src.tcp.port;
		ct->dnat.l4max.all = ct->dnat.l4min.all;
		ct->tuple[__DIR_REPL].l4src.tcp.port =
			ct->tuple[__DIR_ORIG].l4dst.tcp.port;
		set_bit(ATTR_DNAT_PORT, ct->set);
		break;
	case NFCT_SOPT_SETUP_ORIGINAL:
		__autocomplete(ct, __DIR_ORIG);
		break;
	case NFCT_SOPT_SETUP_REPLY:
		__autocomplete(ct, __DIR_REPL);
		break;
	}
	return 0;
}

int __getobjopt(const struct nf_conntrack *ct, unsigned int option)
{
	int ret = -1;

	switch(option) {
	case NFCT_GOPT_IS_SNAT:
		ret = ((test_bit(ATTR_STATUS, ct->set) ? 
		        ct->status & IPS_SRC_NAT_DONE : 1) &&
		       ct->tuple[__DIR_REPL].dst.v4 != 
		       ct->tuple[__DIR_ORIG].src.v4);
		break;
	case NFCT_GOPT_IS_DNAT:
		ret = ((test_bit(ATTR_STATUS, ct->set) ? 
		        ct->status & IPS_DST_NAT_DONE : 1) &&
		       ct->tuple[__DIR_REPL].src.v4 !=
		       ct->tuple[__DIR_ORIG].dst.v4);
		break;
	case NFCT_GOPT_IS_SPAT:
		ret = ((test_bit(ATTR_STATUS, ct->set) ? 
		        ct->status & IPS_SRC_NAT_DONE : 1) &&
		       ct->tuple[__DIR_REPL].l4dst.tcp.port !=
		       ct->tuple[__DIR_ORIG].l4src.tcp.port);
		break;
	case NFCT_GOPT_IS_DPAT:
		ret = ((test_bit(ATTR_STATUS, ct->set) ? 
		        ct->status & IPS_DST_NAT_DONE : 1) &&
		       ct->tuple[__DIR_REPL].l4src.tcp.port !=
		       ct->tuple[__DIR_ORIG].l4dst.tcp.port);
		break;
	}

	return ret;
}
