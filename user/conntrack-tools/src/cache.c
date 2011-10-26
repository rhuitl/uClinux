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
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <errno.h>
#include "us-conntrack.h"
#include "cache.h"

static u_int32_t hash(const void *data, struct hashtable *table)
{
	unsigned int a, b;
	const struct us_conntrack *u = data;
	struct nf_conntrack *ct = u->ct;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC), sizeof(u_int32_t),
		  ((nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_DST), sizeof(u_int32_t),
		  ((nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	return jhash_2words(a, b, 0) % table->hashsize;
}

static u_int32_t hash6(const void *data, struct hashtable *table)
{
	unsigned int a, b;
	const struct us_conntrack *u = data;
	struct nf_conntrack *ct = u->ct;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), sizeof(u_int32_t),
		  ((nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), sizeof(u_int32_t),
		  ((nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	return jhash_2words(a, b, 0) % table->hashsize;
}

static int __compare(const struct nf_conntrack *ct1, 
		     const struct nf_conntrack *ct2)
{
	return ((nfct_get_attr_u8(ct1, ATTR_ORIG_L3PROTO) ==
	  	 nfct_get_attr_u8(ct2, ATTR_ORIG_L3PROTO)) &&
		(nfct_get_attr_u8(ct1, ATTR_ORIG_L4PROTO) ==
		 nfct_get_attr_u8(ct2, ATTR_ORIG_L4PROTO)) && 
		(nfct_get_attr_u16(ct1, ATTR_ORIG_PORT_SRC) ==
		 nfct_get_attr_u16(ct2, ATTR_ORIG_PORT_SRC)) &&
		(nfct_get_attr_u16(ct1, ATTR_ORIG_PORT_DST) ==
	 	 nfct_get_attr_u16(ct2, ATTR_ORIG_PORT_DST)) &&
		(nfct_get_attr_u16(ct1, ATTR_REPL_PORT_SRC) ==
	 	 nfct_get_attr_u16(ct2, ATTR_REPL_PORT_SRC)) &&
		(nfct_get_attr_u16(ct1, ATTR_REPL_PORT_DST) ==
	 	 nfct_get_attr_u16(ct2, ATTR_REPL_PORT_DST)));
}

static int compare(const void *data1, const void *data2)
{
	const struct us_conntrack *u1 = data1;
	const struct us_conntrack *u2 = data2;

	return ((nfct_get_attr_u32(u1->ct, ATTR_ORIG_IPV4_SRC) ==
	         nfct_get_attr_u32(u2->ct, ATTR_ORIG_IPV4_SRC)) &&
	 	(nfct_get_attr_u32(u1->ct, ATTR_ORIG_IPV4_DST) ==
		 nfct_get_attr_u32(u2->ct, ATTR_ORIG_IPV4_DST)) &&
		(nfct_get_attr_u32(u1->ct, ATTR_REPL_IPV4_SRC) ==
		 nfct_get_attr_u32(u2->ct, ATTR_REPL_IPV4_SRC)) &&
		(nfct_get_attr_u32(u1->ct, ATTR_REPL_IPV4_DST) ==
		 nfct_get_attr_u32(u2->ct, ATTR_REPL_IPV4_DST)) &&
		 __compare(u1->ct, u2->ct));
}

static int compare6(const void *data1, const void *data2)
{
	const struct us_conntrack *u1 = data1;
	const struct us_conntrack *u2 = data2;

	return ((nfct_get_attr_u32(u1->ct, ATTR_ORIG_IPV6_SRC) ==
	         nfct_get_attr_u32(u2->ct, ATTR_ORIG_IPV6_SRC)) &&
	 	(nfct_get_attr_u32(u1->ct, ATTR_ORIG_IPV6_DST) ==
		 nfct_get_attr_u32(u2->ct, ATTR_ORIG_IPV6_DST)) &&
		(nfct_get_attr_u32(u1->ct, ATTR_REPL_IPV6_SRC) ==
		 nfct_get_attr_u32(u2->ct, ATTR_REPL_IPV6_SRC)) &&
		(nfct_get_attr_u32(u1->ct, ATTR_REPL_IPV6_DST) ==
		 nfct_get_attr_u32(u2->ct, ATTR_REPL_IPV6_DST)) &&
		 __compare(u1->ct, u2->ct));
}

struct cache_feature *cache_feature[CACHE_MAX_FEATURE] = {
	[TIMER_FEATURE]		= &timer_feature,
	[LIFETIME_FEATURE]	= &lifetime_feature,
};

struct cache *cache_create(char *name, 
			   unsigned int features, 
			   u_int8_t proto,
			   struct cache_extra *extra)
{
	size_t size = sizeof(struct us_conntrack);
	int i, j = 0;
	struct cache *c;
	struct cache_feature *feature_array[CACHE_MAX_FEATURE] = {};
	unsigned int feature_offset[CACHE_MAX_FEATURE] = {};
	unsigned int feature_type[CACHE_MAX_FEATURE] = {};

	c = malloc(sizeof(struct cache));
	if (!c)
		return NULL;
	memset(c, 0, sizeof(struct cache));

	strcpy(c->name, name);

	for (i = 0; i < CACHE_MAX_FEATURE; i++) {
		if ((1 << i) & features) {
			feature_array[j] = cache_feature[i];
			feature_offset[j] = size;
			feature_type[i] = j;
			size += cache_feature[i]->size;
			j++;
		}
	}

	memcpy(c->feature_type, feature_type, sizeof(feature_type));

	c->features = malloc(sizeof(struct cache_feature) * j);
	if (!c->features) {
		free(c);
		return NULL;
	}
	memcpy(c->features, feature_array, sizeof(struct cache_feature) * j);
	c->num_features = j;

	c->extra_offset = size;
	c->extra = extra;
	if (extra)
		size += extra->size;

	c->feature_offset = malloc(sizeof(unsigned int) * j);
	if (!c->feature_offset) {
		free(c->features);
		free(c);
		return NULL;
	}
	memcpy(c->feature_offset, feature_offset, sizeof(unsigned int) * j);

	switch(proto) {
	case AF_INET:
		c->h = hashtable_create(CONFIG(hashsize),
					CONFIG(limit),
					size,
					hash,
					compare);
		break;
	case AF_INET6:
		c->h = hashtable_create(CONFIG(hashsize),
					CONFIG(limit),
					size,
					hash6,
					compare6);
		break;
	}

	if (!c->h) {
		free(c->features);
		free(c->feature_offset);
		free(c);
		return NULL;
	}

	return c;
}

void cache_destroy(struct cache *c)
{
	hashtable_destroy(c->h);
	free(c->features);
	free(c->feature_offset);
	free(c);
}

static struct us_conntrack *__add(struct cache *c, struct nf_conntrack *ct)
{
	int i;
	size_t size = c->h->datasize;
	char buf[size];
	struct us_conntrack *u = (struct us_conntrack *) buf;
	struct nf_conntrack *newct;

	memset(u, 0, size);

	u->cache = c;
	if ((u->ct = newct = nfct_new()) == NULL) {
		errno = ENOMEM;
		return 0;
	}
	memcpy(u->ct, ct, nfct_sizeof(ct));

	u = hashtable_add(c->h, u);
	if (u) {
		void *data = u->data;

        	for (i = 0; i < c->num_features; i++) {
			c->features[i]->add(u, data);
			data += c->features[i]->size;
		}

		if (c->extra && c->extra->add)
			c->extra->add(u, ((void *) u) + c->extra_offset);

		return u;
	}
	free(newct);

	return NULL;
}

struct us_conntrack *cache_add(struct cache *c, struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	u = __add(c, ct);
	if (u) {
		c->add_ok++;
		return u;
	}
	if (errno != EEXIST)
		c->add_fail++;

	return NULL;
}

static struct us_conntrack *__update(struct cache *c, struct nf_conntrack *ct)
{
	size_t size = c->h->datasize;
	char buf[size];
	struct us_conntrack *u = (struct us_conntrack *) buf;

	u->ct = ct;

	u = (struct us_conntrack *) hashtable_test(c->h, u);
	if (u) {
		int i;
		void *data = u->data;

		for (i = 0; i < c->num_features; i++) {
			c->features[i]->update(u, data);
			data += c->features[i]->size;
		}

		if (c->extra && c->extra->update)
			c->extra->update(u, ((void *) u) + c->extra_offset);

		if (nfct_attr_is_set(ct, ATTR_STATUS))
		    	nfct_set_attr_u32(u->ct, ATTR_STATUS,
					  nfct_get_attr_u32(ct, ATTR_STATUS));
		if (nfct_attr_is_set(ct, ATTR_TCP_STATE))
			nfct_set_attr_u8(u->ct, ATTR_TCP_STATE,
					 nfct_get_attr_u8(ct, ATTR_TCP_STATE));
		if (nfct_attr_is_set(ct, ATTR_TIMEOUT))
			nfct_set_attr_u32(u->ct, ATTR_TIMEOUT,
					  nfct_get_attr_u32(ct, ATTR_TIMEOUT));

		return u;
	} 
	return NULL;
}

struct us_conntrack *__cache_update(struct cache *c, struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	u = __update(c, ct);
	if (u) {
		c->upd_ok++;
		return u;
	}
	c->upd_fail++;
	
	return NULL;
}

struct us_conntrack *cache_update(struct cache *c, struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	u = __cache_update(c, ct);

	return u;
}

struct us_conntrack *cache_update_force(struct cache *c,
					struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	if ((u = __update(c, ct)) != NULL) {
		c->upd_ok++;
		return u;
	}
	if ((u = __add(c, ct)) != NULL) {
		c->add_ok++;
		return u;
	}
	c->add_fail++;
	return NULL;
}

int cache_test(struct cache *c, struct nf_conntrack *ct)
{
	size_t size = c->h->datasize;
	char buf[size];
	struct us_conntrack *u = (struct us_conntrack *) buf;
	void *ret;

	u->ct = ct;

	ret = hashtable_test(c->h, u);

	return ret != NULL;
}

static int __del(struct cache *c, struct nf_conntrack *ct)
{
	size_t size = c->h->datasize;
	char buf[size];
	struct us_conntrack *u = (struct us_conntrack *) buf;

	u->ct = ct;

	u = (struct us_conntrack *) hashtable_test(c->h, u);
	if (u) {
		int i;
		void *data = u->data;
		struct nf_conntrack *p = u->ct;

		for (i = 0; i < c->num_features; i++) {
			c->features[i]->destroy(u, data);
			data += c->features[i]->size;
		}

		if (c->extra && c->extra->destroy)
			c->extra->destroy(u, ((void *) u) + c->extra_offset);

		hashtable_del(c->h, u);
		free(p);
		return 1;
	}
	return 0;
}

int cache_del(struct cache *c, struct nf_conntrack *ct)
{
	if (__del(c, ct)) {
		c->del_ok++;
		return 1;
	}
	c->del_fail++;

	return 0;
}

struct us_conntrack *cache_get_conntrack(struct cache *c, void *data)
{
	return data - c->extra_offset;
}

void *cache_get_extra(struct cache *c, void *data)
{
	return data + c->extra_offset;
}

void cache_stats(struct cache *c, int fd)
{
	char buf[512];
	int size;

	size = sprintf(buf, "cache %s:\n"
			    "current active connections:\t%12u\n"
			    "connections created:\t\t%12u\tfailed:\t%12u\n"
			    "connections updated:\t\t%12u\tfailed:\t%12u\n"
			    "connections destroyed:\t\t%12u\tfailed:\t%12u\n\n",
			    			 c->name,
			    			 hashtable_counter(c->h),
			    			 c->add_ok, 
			    			 c->add_fail,
						 c->upd_ok,
						 c->upd_fail,
						 c->del_ok,
						 c->del_fail);
	send(fd, buf, size, 0);
}

void cache_iterate(struct cache *c, 
		   void *data, 
		   int (*iterate)(void *data1, void *data2))
{
	hashtable_iterate(c->h, data, iterate);
}
