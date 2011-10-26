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

#include "cache.h"
#include "jhash.h"
#include "hash.h"
#include "conntrackd.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <errno.h>
#include "us-conntrack.h"

struct __dump_container {
	int fd;
	int type;
};

static int do_dump(void *data1, void *data2)
{
	char buf[1024];
	int size;
	struct __dump_container *container = data1;
	struct us_conntrack *u = data2;
	void *data = u->data;
	int i;

	memset(buf, 0, sizeof(buf));
	size = nfct_snprintf(buf, 
			     sizeof(buf), 
			     u->ct, 
			     NFCT_T_UNKNOWN, 
			     container->type,
			     0);

	for (i = 0; i < u->cache->num_features; i++) {
		if (u->cache->features[i]->dump) {
			size += u->cache->features[i]->dump(u, 
							    data, 
							    buf+size,
							    container->type);
			data += u->cache->features[i]->size;
		}
	}
	size += sprintf(buf+size, "\n");
	if (send(container->fd, buf, size, 0) == -1) {
		if (errno != EPIPE)
			return -1;
	}

	return 0;
}

void cache_dump(struct cache *c, int fd, int type)
{
	struct __dump_container tmp = {
		.fd	= fd,
		.type	= type
	};

	hashtable_iterate(c->h, (void *) &tmp, do_dump);
}

/* no need to clone, called from child process */
static int do_commit(void *data1, void *data2)
{
	int ret;
	struct cache *c = data1;
	struct us_conntrack *u = data2;
	struct nf_conntrack *ct = u->ct;

	/* XXX: related connections */
	if (nfct_attr_is_set(ct, ATTR_STATUS)) {
		u_int32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
		status &= ~IPS_EXPECTED;
		nfct_set_attr_u32(ct, ATTR_STATUS, status);
	}

	nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

        /* 
	 * Set a reduced timeout for candidate-to-be-committed
	 * conntracks that live in the external cache
	 */
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, CONFIG(commit_timeout));

	if (ret == -1) {
		dlog(STATE(log), "failed to build: %s", strerror(errno));
		return 0;
	}

	ret = nfct_query(STATE(dump), NFCT_Q_CREATE_UPDATE, ct);
	if (ret == -1) {
		switch(errno) {
			case EEXIST:
				c->commit_exist++;
				break;
			default:
				c->commit_fail++;
				break;
		}
	} else {
		c->commit_ok++;
	}

	/* keep iterating even if we have found errors */
	return 0;
}

void cache_commit(struct cache *c)
{
	unsigned int commit_ok = c->commit_ok;
	unsigned int commit_exist = c->commit_exist;
	unsigned int commit_fail = c->commit_fail;

	hashtable_iterate(c->h, c, do_commit);

	/* calculate new entries committed */
	commit_ok = c->commit_ok - commit_ok;
	commit_fail = c->commit_fail - commit_fail;
	commit_exist = c->commit_exist - commit_exist;

	/* log results */
	dlog(STATE(log), "Committed %u new entries", commit_ok);

	if (commit_exist)
		dlog(STATE(log), "%u entries ignored, "
				 "already exist", commit_exist);
	if (commit_fail)
		dlog(STATE(log), "%u entries can't be "
				 "committed", commit_fail);
}

static int do_flush(void *data1, void *data2)
{
	struct cache *c = data1;
	struct us_conntrack *u = data2;

	cache_del(c, u->ct);

	return 0;
}

void cache_flush(struct cache *c)
{
	hashtable_iterate(c->h, c, do_flush);
	c->flush++;
}
