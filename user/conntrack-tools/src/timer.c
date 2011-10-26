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
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "conntrackd.h"
#include "timer.h"

#define TIMESLICE_CREDIT (1000000 / STEPS_PER_SECONDS) /* 200 ms timeslice */

void timer_init(struct timer *timer)
{
	memset(timer, 0, sizeof(struct timer));
	timer->credits = TIMESLICE_CREDIT;
}

void timer_start(struct timer *timer)
{
	gettimeofday(&timer->start, NULL);
}

static int timeval_subtract(struct timeval *diff, 
			    struct timeval *start, 
			    struct timeval *stop)
{
	diff->tv_sec = stop->tv_sec - start->tv_sec;
	diff->tv_usec = stop->tv_usec - start->tv_usec;

	if (diff->tv_usec < 0) {
		diff->tv_usec += 1000000;
		diff->tv_sec--;
	}

	/* Return 1 if result is negative. */
	return diff->tv_sec < 0;
}

void timer_stop(struct timer *timer)
{
	gettimeofday(&timer->stop, NULL);
	timeval_subtract(&timer->diff, &timer->start, &timer->stop);
}

int timer_adjust_credit(struct timer *timer)
{
	if (timer->diff.tv_sec != 0) {
		timer->credits = TIMESLICE_CREDIT;
		return 1;
	}

	timer->credits -= timer->diff.tv_usec;

	if (timer->credits < 0) {
		timer->credits += TIMESLICE_CREDIT;
		if (timer->credits < 0)
			timer->credits = TIMESLICE_CREDIT;
		return 1;
	}
	return 0;
}
