/* vi: set sw=4 ts=4: */
/*
 * getpid() for uClibc
 *
 * Copyright (C) 2000-2006 by Erik Andersen <andersen@codepoet.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

extern __typeof(getpid) __libc_getpid;
#if defined __NR_getxpid
# define __NR_getpid __NR_getxpid
#endif
#define __NR___libc_getpid __NR_getpid
_syscall0(pid_t, __libc_getpid);
libc_hidden_proto(getpid)
weak_alias(__libc_getpid, getpid)
libc_hidden_weak(getpid)
