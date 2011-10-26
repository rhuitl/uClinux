/* vi: set sw=4 ts=4: */
/*
 * msync() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#ifdef __NR_msync

#include <sys/mman.h>

extern __typeof(msync) __libc_msync;
#define __NR___libc_msync __NR_msync
_syscall3(int, __libc_msync, void *, addr, size_t, length, int, flags);
weak_alias(__libc_msync,msync)

#endif
