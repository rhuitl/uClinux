/*
 * timer.h - This timer structure was originally based upon the one in
 *           the linux kernel, but has since evolved somewhat.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

struct timer_lst {
        struct timer_lst *next;
        struct timer_lst *prev;
        unsigned long expires;			/* how long till expiration */
	unsigned long expected;			/* expected time of timeout */
        unsigned long data;			/* data to pass to function */
        void (*function)(unsigned long);	/* func to call on timeout */
};

extern void add_timer(struct timer_lst * timer);
extern int  del_timer(struct timer_lst * timer);
extern void init_timer(struct timer_lst * timer);
extern void adjust_timer(void);
extern unsigned long timestamp(void);
