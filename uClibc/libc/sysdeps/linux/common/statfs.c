/* vi: set sw=4 ts=4: */
/*
 * statfs() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <string.h>
#include <sys/param.h>
#include <sys/vfs.h>

libc_hidden_proto(statfs)
_syscall2(int, statfs, const char *, path, struct statfs *, buf);
libc_hidden_def(statfs)
