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

#include "jhash.h"
#include "hash.h"
#include "conntrackd.h"
#include "ignore.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define IGNORE_POOL_SIZE 32
#define IGNORE_POOL_LIMIT 1024

static u_int32_t hash(const void *data, struct hashtable *table)
{
	const u_int32_t *ip = data;

	return jhash_1word(*ip, 0) % table->hashsize;
}

static u_int32_t hash6(const void *data, struct hashtable *table)
{
	return jhash(data, sizeof(u_int32_t)*4, 0) % table->hashsize;
}

static int compare(const void *data1, const void *data2)
{
	const u_int32_t *ip1 = data1;
	const u_int32_t *ip2 = data2;

	return *ip1 == *ip2;
}

static int compare6(const void *data1, const void *data2)
{
	return memcmp(data1, data2, sizeof(u_int32_t)*4) == 0;
}

struct ignore_pool *ignore_pool_create(u_int8_t proto)
{
	int i, j = 0;
	struct ignore_pool *ip;

	ip = malloc(sizeof(struct ignore_pool));
	if (!ip)
		return NULL;
	memset(ip, 0, sizeof(struct ignore_pool));

	switch(proto) {
	case AF_INET:
		ip->h = hashtable_create(IGNORE_POOL_SIZE,
					 IGNORE_POOL_LIMIT,
					 sizeof(u_int32_t),
					 hash,
					 compare);
		break;
	case AF_INET6:
		ip->h = hashtable_create(IGNORE_POOL_SIZE,
					 IGNORE_POOL_LIMIT,
					 sizeof(u_int32_t)*4,
					 hash6,
					 compare6);
		break;
	}

	if (!ip->h) {
		free(ip);
		return NULL;
	}

	return ip;
}

void ignore_pool_destroy(struct ignore_pool *ip)
{
	hashtable_destroy(ip->h);
	free(ip);
}

int ignore_pool_add(struct ignore_pool *ip, void *data)
{
	if (!hashtable_add(ip->h, data))
		return 0;

	return 1;
}

int __ignore_pool_test_ipv4(struct ignore_pool *ip, struct nf_conntrack *ct)
{
	return (hashtable_test(ip->h, nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC)) ||
		hashtable_test(ip->h, nfct_get_attr(ct, ATTR_ORIG_IPV4_DST)) ||
		hashtable_test(ip->h, nfct_get_attr(ct, ATTR_REPL_IPV4_SRC)) ||
		hashtable_test(ip->h, nfct_get_attr(ct, ATTR_REPL_IPV4_DST)));
}

int __ignore_pool_test_ipv6(struct ignore_pool *ip, struct nf_conntrack *ct)
{
	return (hashtable_test(ip->h, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC)) ||
	        hashtable_test(ip->h, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST)) ||
	        hashtable_test(ip->h, nfct_get_attr(ct, ATTR_REPL_IPV6_SRC)) ||
	        hashtable_test(ip->h, nfct_get_attr(ct, ATTR_REPL_IPV6_DST)));
}

int ignore_pool_test(struct ignore_pool *ip, struct nf_conntrack *ct)
{
	int ret;

	switch(nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO)) {
	case AF_INET:
		ret = __ignore_pool_test_ipv4(ip, ct);
		break;
	case AF_INET6:
		ret = __ignore_pool_test_ipv6(ip, ct);
		break;
	default:
		dlog(STATE(log), "unknown conntrack layer 3 protocol?");
		break;
	}

	return ret;
}
