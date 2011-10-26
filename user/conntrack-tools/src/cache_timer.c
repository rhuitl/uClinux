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

static void timeout(struct alarm_list *a, void *data)
{
	struct us_conntrack *u = data;

	debug_ct(u->ct, "expired timeout");
	cache_del(u->cache, u->ct);
}

static void timer_add(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;

	init_alarm(alarm);
	set_alarm_expiration(alarm, CONFIG(cache_timeout));
	set_alarm_data(alarm, u);
	set_alarm_function(alarm, timeout);
	add_alarm(alarm);
}

static void timer_update(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;
	mod_alarm(alarm, CONFIG(cache_timeout));
}

static void timer_destroy(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;
	del_alarm(alarm);
}

static int timer_dump(struct us_conntrack *u, void *data, char *buf, int type)
{
 	struct alarm_list *alarm = data;

	if (type == NFCT_O_XML)
		return 0;

	return sprintf(buf, " [expires in %ds]", alarm->expires);
}

struct cache_feature timer_feature = {
	.size		= sizeof(struct alarm_list),
	.add		= timer_add,
	.update		= timer_update,
	.destroy	= timer_destroy,
	.dump		= timer_dump
};
