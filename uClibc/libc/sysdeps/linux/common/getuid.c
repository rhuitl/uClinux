/* vi: set sw=4 ts=4: */
/*
 * getuid() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#if defined __NR_getxuid
# undef __NR_getuid
# define __NR_getuid __NR_getxuid
#endif
#ifdef __NR_getuid32
# undef __NR_getuid
# define __NR_getuid __NR_getuid32
#endif

libc_hidden_proto(getuid)
_syscall0(uid_t, getuid);
libc_hidden_def(getuid)
