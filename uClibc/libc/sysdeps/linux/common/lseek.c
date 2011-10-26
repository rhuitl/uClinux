/* vi: set sw=4 ts=4: */
/*
 * lseek() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

extern __typeof(lseek) __libc_lseek;
libc_hidden_proto(__libc_lseek)

#ifdef __NR_lseek
#define __NR___libc_lseek __NR_lseek
_syscall3(__off_t, __libc_lseek, int, fildes, __off_t, offset, int, whence);
#else
extern __typeof(lseek64) __libc_lseek64;
libc_hidden_proto(__libc_lseek64)
__off_t __libc_lseek(int fildes, __off_t offset, int whence)
{
	return __libc_lseek64(fildes, offset, whence);
}
#endif
libc_hidden_def(__libc_lseek)

libc_hidden_proto(lseek)
weak_alias(__libc_lseek,lseek)
libc_hidden_weak(lseek)
