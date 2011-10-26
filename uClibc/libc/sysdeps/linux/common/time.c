/* vi: set sw=4 ts=4: */
/*
 * time() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <time.h>
#include <sys/time.h>

libc_hidden_proto(time)

#ifdef __NR_time
_syscall1(time_t, time, time_t *, t);
#else
libc_hidden_proto(gettimeofday)

time_t time(time_t * t)
{
	time_t result;
	struct timeval tv;

	if (gettimeofday(&tv, (struct timezone *) NULL)) {
		result = (time_t) - 1;
	} else {
		result = (time_t) tv.tv_sec;
	}
	if (t != NULL) {
		*t = result;
	}
	return result;
}
#endif
libc_hidden_def(time)
