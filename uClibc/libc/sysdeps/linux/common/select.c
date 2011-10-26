/* vi: set sw=4 ts=4: */
/*
 * select() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/select.h>

extern __typeof(select) __libc_select;

#ifdef __NR__newselect
# define __NR___libc_select __NR__newselect
#else
# define __NR___libc_select __NR_select
#endif
_syscall5(int, __libc_select, int, n, fd_set *, readfds, fd_set *, writefds,
		  fd_set *, exceptfds, struct timeval *, timeout);
libc_hidden_proto(select)
weak_alias(__libc_select,select)
libc_hidden_weak(select)
