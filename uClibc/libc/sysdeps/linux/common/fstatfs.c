/* vi: set sw=4 ts=4: */
/*
 * fstatfs() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/vfs.h>

libc_hidden_proto(fstatfs)

_syscall2(int, fstatfs, int, fd, struct statfs *, buf);
libc_hidden_def(fstatfs)
