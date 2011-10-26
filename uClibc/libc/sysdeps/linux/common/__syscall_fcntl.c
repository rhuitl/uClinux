/* vi: set sw=4 ts=4: */
/*
 * __syscall_fcntl() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdarg.h>
#include <fcntl.h>
#include <bits/wordsize.h>

extern __typeof(fcntl) __libc_fcntl;
libc_hidden_proto(__libc_fcntl)

#if defined __UCLIBC_HAS_LFS__ && defined __NR_fcntl64
extern __typeof(fcntl64) __libc_fcntl64;
libc_hidden_proto(__libc_fcntl64)
#endif

#define __NR___syscall_fcntl __NR_fcntl
static inline
_syscall3(int, __syscall_fcntl, int, fd, int, cmd, long, arg);

int __libc_fcntl(int fd, int cmd, ...)
{
	long arg;
	va_list list;

	va_start(list, cmd);
	arg = va_arg(list, long);
	va_end(list);

#if __WORDSIZE == 32
	if (cmd == F_GETLK64 || cmd == F_SETLK64 || cmd == F_SETLKW64) {
#if defined __UCLIBC_HAS_LFS__ && defined __NR_fcntl64
		return __libc_fcntl64(fd, cmd, arg);
#else
		__set_errno(ENOSYS);
		return -1;
#endif
	}
#endif

	return (__syscall_fcntl(fd, cmd, arg));
}
libc_hidden_def(__libc_fcntl)

libc_hidden_proto(fcntl)
weak_alias(__libc_fcntl,fcntl)
libc_hidden_weak(fcntl)
#if ! defined __NR_fcntl64 && defined __UCLIBC_HAS_LFS__
strong_alias(__libc_fcntl,__libc_fcntl64)
libc_hidden_proto(fcntl64)
weak_alias(__libc_fcntl,fcntl64)
libc_hidden_weak(fcntl64)
#endif
