/*
 * clock_gettime() for uClibc
 *
 * Copyright (C) 2003 by Justus Pendleton <uc@ryoohki.net>
 * Copyright (C) 2005 by Peter Kjellerstedt <pkj@axis.com>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <time.h>
#include <sys/time.h>

#ifdef __NR_clock_gettime
_syscall2(int, clock_gettime, clockid_t, clock_id, struct timespec*, tp);
#else
libc_hidden_proto(gettimeofday)

int clock_gettime(clockid_t clock_id, struct timespec* tp)
{
	struct timeval tv;
	int retval = -1;

	switch (clock_id) {
		case CLOCK_REALTIME:
			retval = gettimeofday(&tv, NULL);
			if (retval == 0) {
				TIMEVAL_TO_TIMESPEC(&tv, tp);
			}
			break;

		default:
			__set_errno(EINVAL);
			break;
	}

	return retval;
}
#endif
