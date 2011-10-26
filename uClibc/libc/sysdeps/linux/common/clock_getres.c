/*
 * clock_getres() for uClibc
 *
 * Copyright (C) 2005 by Peter Kjellerstedt <pkj@axis.com>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifdef __NR_clock_getres
_syscall2(int, clock_getres, clockid_t, clock_id, struct timespec*, res);
#else
libc_hidden_proto(sysconf)

int clock_getres(clockid_t clock_id, struct timespec* res)
{
	int retval = -1;

	switch (clock_id) {
		case CLOCK_REALTIME:
			if (res) {
				long clk_tck;

				if ((clk_tck = sysconf(_SC_CLK_TCK)) < 0)
					clk_tck = 100;
				res->tv_sec = 0;
				res->tv_nsec = 1000000000 / clk_tck;
			}
			retval = 0;
			break;

		default:
			__set_errno(EINVAL);
			break;
	}

	return retval;
}
#endif
