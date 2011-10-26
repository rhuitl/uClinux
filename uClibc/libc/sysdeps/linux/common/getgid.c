/* vi: set sw=4 ts=4: */
/*
 * getgid() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#if defined __NR_getxgid
# undef __NR_getgid
# define __NR_getgid __NR_getxgid
#endif
#ifdef __NR_getgid32
# undef __NR_getgid
# define __NR_getgid __NR_getgid32
#endif

libc_hidden_proto(getgid)
_syscall0(gid_t, getgid);
libc_hidden_def(getgid)
