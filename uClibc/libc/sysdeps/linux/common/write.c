/* vi: set sw=4 ts=4: */
/*
 * write() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

extern __typeof(write) __libc_write;
#define __NR___libc_write __NR_write
_syscall3(ssize_t, __libc_write, int, fd, const __ptr_t, buf, size_t, count);
libc_hidden_proto(write)
weak_alias(__libc_write,write)
libc_hidden_weak(write)
#if 0
/* Stupid libgcc.a from gcc 2.95.x uses __write in pure.o
 * which is a blatent GNU libc-ism... */
strong_alias(__libc_write,__write)
#endif
