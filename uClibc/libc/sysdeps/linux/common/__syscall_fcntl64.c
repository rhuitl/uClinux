/* vi: set sw=4 ts=4: */
/*
 * __syscall_fcntl64() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdarg.h>
#include <fcntl.h>

#if defined __UCLIBC_HAS_LFS__ && defined __NR_fcntl64
extern __typeof(fcntl64) __libc_fcntl64;
libc_hidden_proto(__libc_fcntl64)

#define __NR___syscall_fcntl64 __NR_fcntl64
static inline _syscall3(int, __syscall_fcntl64, int, fd, int, cmd, long, arg);
int __libc_fcntl64(int fd, int cmd, ...)
{
	long arg;
	va_list list;

	va_start(list, cmd);
	arg = va_arg(list, long);
	va_end(list);

	return (__syscall_fcntl64(fd, cmd, arg));
}
libc_hidden_def(__libc_fcntl64)

libc_hidden_proto(fcntl64)
strong_alias(__libc_fcntl64,fcntl64)
libc_hidden_weak(fcntl64)
#endif
