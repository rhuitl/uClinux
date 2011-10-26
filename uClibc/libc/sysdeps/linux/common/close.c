/* vi: set sw=4 ts=4: */
/*
 * close() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

extern __typeof(close) __libc_close;
#define __NR___libc_close __NR_close
_syscall1(int, __libc_close, int, fd);
libc_hidden_proto(close)
weak_alias(__libc_close,close)
libc_hidden_weak(close)
