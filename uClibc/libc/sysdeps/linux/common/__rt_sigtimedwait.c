/* vi: set sw=4 ts=4: */
/*
 * __rt_sigtimedwait() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <signal.h>
#define __need_NULL
#include <stddef.h>

libc_hidden_proto(sigwaitinfo)
libc_hidden_proto(sigtimedwait)

#ifdef __NR_rt_sigtimedwait
#define __NR___rt_sigtimedwait __NR_rt_sigtimedwait
static _syscall4(int, __rt_sigtimedwait, const sigset_t *, set, siginfo_t *, info,
		  const struct timespec *, timeout, size_t, setsize);

int sigwaitinfo(const sigset_t * set, siginfo_t * info)
{
	return __rt_sigtimedwait(set, info, NULL, _NSIG / 8);
}

int sigtimedwait(const sigset_t * set, siginfo_t * info,
				 const struct timespec *timeout)
{
	return __rt_sigtimedwait(set, info, timeout, _NSIG / 8);
}
#else
int sigwaitinfo(const sigset_t * set, siginfo_t * info)
{
	if (set == NULL)
		__set_errno(EINVAL);
	else
		__set_errno(ENOSYS);
	return -1;
}

int sigtimedwait(const sigset_t * set, siginfo_t * info,
				 const struct timespec *timeout)
{
	if (set == NULL)
		__set_errno(EINVAL);
	else
		__set_errno(ENOSYS);
	return -1;
}
#endif
libc_hidden_def(sigwaitinfo)
libc_hidden_def(sigtimedwait)
