/* vi: set sw=4 ts=4: */
/*
 * uname() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/utsname.h>

libc_hidden_proto(uname)

_syscall1(int, uname, struct utsname *, buf);
libc_hidden_def(uname)
