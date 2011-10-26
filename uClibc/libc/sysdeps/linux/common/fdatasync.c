/* vi: set sw=4 ts=4: */
/*
 * fdatasync() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#if defined __NR_osf_fdatasync
# define __NR_fdatasync __NR_osf_fdatasync
#endif

_syscall1(int, fdatasync, int, fd);
