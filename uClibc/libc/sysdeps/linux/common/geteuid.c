/* vi: set sw=4 ts=4: */
/*
 * geteuid() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

libc_hidden_proto(geteuid)

#if defined(__NR_geteuid32)
# undef __NR_geteuid
# define __NR_geteuid __NR_geteuid32
_syscall0(uid_t, geteuid);

#elif defined(__NR_geteuid)
# define __NR___syscall_geteuid __NR_geteuid
static inline _syscall0(int, __syscall_geteuid);
uid_t geteuid(void)
{
	return (__syscall_geteuid());
}

#else
libc_hidden_proto(getuid)
uid_t geteuid(void)
{
	return (getuid());
}
#endif

libc_hidden_def(geteuid)
