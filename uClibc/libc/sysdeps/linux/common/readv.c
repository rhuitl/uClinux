/* vi: set sw=4 ts=4: */
/*
 * readv() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/uio.h>

extern __typeof(readv) __libc_readv;

#define __NR___libc_readv __NR_readv
_syscall3(ssize_t, __libc_readv, int, filedes, const struct iovec *, vector,
		  int, count);
weak_alias(__libc_readv,readv)
