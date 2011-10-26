/* vi: set sw=4 ts=4: */
/*
 * writev() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/uio.h>

extern __typeof(writev) __libc_writev;

#define __NR___libc_writev __NR_writev
_syscall3(ssize_t, __libc_writev, int, filedes, const struct iovec *, vector,
		  int, count);
weak_alias(__libc_writev,writev)
