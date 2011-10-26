/* vi: set sw=4 ts=4: */
/*
 * fsync() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

extern __typeof(fsync) __libc_fsync;
#define __NR___libc_fsync __NR_fsync
_syscall1(int, __libc_fsync, int, fd);
weak_alias(__libc_fsync, fsync)
