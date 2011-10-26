/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
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

#include <stdio.h>
#include "conntrackd.h"
#include "us-conntrack.h"
#include "cache.h"
#include "alarm.h"

static void lifetime_add(struct us_conntrack *u, void *data)
{
	long *lifetime = data;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	*lifetime = tv.tv_sec;
}

static void lifetime_update(struct us_conntrack *u, void *data)
{
}

static void lifetime_destroy(struct us_conntrack *u, void *data)
{
}

static int lifetime_dump(struct us_conntrack *u, 
			 void *data, 
			 char *buf, 
			 int type)
{
	long *lifetime = data;
	struct timeval tv;

	if (type == NFCT_O_XML)
		return 0;

	gettimeofday(&tv, NULL);

	return sprintf(buf, " [active since %lds]", tv.tv_sec - *lifetime);
}

struct cache_feature lifetime_feature = {
	.size		= sizeof(long),
	.add		= lifetime_add,
	.update		= lifetime_update,
	.destroy	= lifetime_destroy,
	.dump		= lifetime_dump
};
