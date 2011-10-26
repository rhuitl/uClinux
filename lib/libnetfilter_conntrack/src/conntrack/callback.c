/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

int __callback(struct nlmsghdr *nlh, struct nfattr *nfa[], void *data)
{
	int ret = NFNL_CB_STOP;
	unsigned int type;
	struct nf_conntrack *ct;
	int len = nlh->nlmsg_len;
	struct __data_container *container = data;

	len -= NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0)
		return NFNL_CB_CONTINUE;

	type = __parse_message_type(nlh);
	if (!(type & container->type))
		return NFNL_CB_CONTINUE;

	ct = nfct_new();
	if (!ct)
		return NFNL_CB_CONTINUE;

	__parse_conntrack(nlh, nfa, ct);

	if (container->h->cb)
		ret = container->h->cb(type, ct, container->data);

	switch(ret) {
	case NFCT_CB_FAILURE:
		free(ct);
		ret = NFNL_CB_FAILURE;
		break;
	case NFCT_CB_STOP:
		free(ct);
		ret = NFNL_CB_STOP;
		break;
	case NFCT_CB_CONTINUE:
		free(ct);
		ret = NFNL_CB_CONTINUE;
		break;
	case NFCT_CB_STOLEN:
		ret = NFNL_CB_CONTINUE;
		break;
	}
	return ret;
}
