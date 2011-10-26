/* ulogd, Version $LastChangedRevision: 476 $
 *
 * $Id: ulogd.c 476 2004-07-23 03:19:35Z laforge $
 *
 * userspace logging daemon for the netfilter subsystem
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <ulogd/ulogd.h>
#include <ulogd/linuxlist.h>

static LLIST_HEAD(ulogd_timers);

static void tv_normalize(struct timeval *out)
{
	out->tv_sec += (out->tv_usec / 1000000);
	out->tv_usec = (out->tv_usec % 1000000);
}

/* subtract two struct timevals */
static int tv_sub(struct timeval *res, const struct timeval *from,
		  const struct timeval *sub)
{
	/* FIXME: this stinks.  Deal with wraps, carry, ... */
	res->tv_sec = from->tv_sec - sub->tv_sec;
	res->tv_usec = from->tv_usec - sub->tv_usec;

	return 0;
}

static int tv_add(struct timeval *res, const struct timeval *a1,
		  const struct timeval *a2)
{
	unsigned int carry;

	res->tv_sec = a1->tv_sec + a2->tv_sec;
	res->tv_usec = a1->tv_usec + a2->tv_usec;

	tv_normalize(res);
}

static int tv_later(const struct timeval *expires, const struct timeval *now)
{
	if (expires->tv_sec < now->tv_sec)
		return 0;
	else if (expires->tv_sec > now->tv_sec)
		return 1;
	else /* if (expires->tv_sec == now->tv_sec */ {
		if (expires->tv_usec >= now->tv_usec)
			return 1;
	}

	return 0;
}

static int tv_smaller(const struct timeval *t1, const struct timeval *t2)
{
	return tv_later(t2, t1);
}

static int calc_next_expiration(void)
{
	struct ulogd_timer *cur;
	struct timeval min, now, diff;
	struct itimerval iti;
	int ret;

retry:
	if (llist_empty(&ulogd_timers))
		return 0;

	llist_for_each_entry(cur, &ulogd_timers, list) {
		if (ulogd_timers.next == &cur->list)
			min = cur->expires;

		if (tv_smaller(&cur->expires, &min))
			min = cur->expires;
	}

	if (tv_sub(&diff, &min, &now) < 0) {
		/* FIXME: run expired timer callbacks */
		/* we cannot run timers from here since we might be
		 * called from register_timer() within check_n_run() */

		/* FIXME: restart with next minimum timer */
		goto retry;
	}

	/* re-set kernel timer */
	memset(&iti, 0, sizeof(iti));
	memcpy(&iti.it_value, &diff, sizeof(iti.it_value));
	ret = setitimer(ITIMER_REAL, &iti, NULL);
	if (ret < 0)
		return ret;

	return 0;
}

void ulogd_timer_check_n_run(void)
{
	struct ulogd_timer *cur, *cur2;
	struct timeval now;

	if (gettimeofday(&now, NULL) < 0)
		return;

	llist_for_each_entry_safe(cur, cur2, &ulogd_timers, list) {
		if (tv_later(&cur->expires, &now)) {
			/* fist delete it from the list of timers */
			llist_del(cur);
			/* then call.  called function can re-add it */
			(cur->cb)(cur->data);
		}
	}

	calc_next_expiration();
}


int ulogd_register_timer(struct ulogd_timer *timer)
{
	int ret;
	struct timeval tv;

	ret = gettimeofday(&tv, NULL);
	if (ret < 0)
		return ret;

	/* convert expiration time into absoulte time */
	timer->expires.tv_sec += tv.tv_sec;
	timer->expires.tv_usec += tv.tv_usec;

	llist_add_tail(&timer->list, &ulogd_timers);

	/* re-calculate next expiration */
	calc_next_expiration();

	return 0;
}

void ulogd_unregister_timer(struct ulogd_timer *timer)
{
	llist_del(&timer->list);

	/* re-calculate next expiration */
	calc_next_expiration();
}
