/* vi: set sw=4 ts=4: */
/*
 * sigsuspend() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <signal.h>

extern __typeof(sigsuspend) __libc_sigsuspend;

#ifdef __NR_rt_sigsuspend
# define __NR___rt_sigsuspend __NR_rt_sigsuspend
static inline _syscall2(int, __rt_sigsuspend, const sigset_t *, mask, size_t, size);

int __libc_sigsuspend(const sigset_t * mask)
{
	return __rt_sigsuspend(mask, _NSIG / 8);
}
#else
# define __NR___syscall_sigsuspend __NR_sigsuspend
static inline _syscall3(int, __syscall_sigsuspend, int, a, unsigned long int, b,
		  unsigned long int, c);

int __libc_sigsuspend(const sigset_t * set)
{
	return __syscall_sigsuspend(0, 0, set->__val[0]);
}
#endif
libc_hidden_proto(sigsuspend)
weak_alias(__libc_sigsuspend,sigsuspend)
libc_hidden_weak(sigsuspend)
