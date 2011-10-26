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

static int tcp_verdict(const struct state_replication_helper *h,
		       const struct nf_conntrack *ct)
{
	u_int8_t state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
	if (h->state & (1 << state))
		return ST_H_REPLICATE;

	return ST_H_SKIP;
}

struct state_replication_helper tcp_state_helper = {
	.proto 		= IPPROTO_TCP,
	.verdict 	= tcp_verdict,
};
