/* vi: set sw=4 ts=4: */
/*
 * nanosleep() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <time.h>

extern __typeof(nanosleep) __libc_nanosleep;
#define __NR___libc_nanosleep __NR_nanosleep
_syscall2(int, __libc_nanosleep, const struct timespec *, req,
		  struct timespec *, rem);
libc_hidden_proto(nanosleep)
weak_alias(__libc_nanosleep,nanosleep)
libc_hidden_weak(nanosleep)
