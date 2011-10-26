/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "conntrackd.h"
#include "state_helper.h"

static struct state_replication_helper *helper[IPPROTO_MAX];

int state_helper_verdict(int type, struct nf_conntrack *ct) 
{
	u_int8_t l4proto;

        if (type == NFCT_Q_DESTROY)
		return ST_H_REPLICATE;

	l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	if (helper[l4proto])
		return helper[l4proto]->verdict(helper[l4proto], ct);

	return ST_H_REPLICATE;
}

void state_helper_register(struct state_replication_helper *h, int state)
{
	if (helper[h->proto] == NULL)
		helper[h->proto] = h;

	helper[h->proto]->state |= (1 << state);
}
