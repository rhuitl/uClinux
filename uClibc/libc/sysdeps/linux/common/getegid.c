/* vi: set sw=4 ts=4: */
/*
 * getegid() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

libc_hidden_proto(getegid)

#if defined(__NR_getegid32)
# undef __NR_getegid
# define __NR_getegid __NR_getegid32
_syscall0(gid_t, getegid);

#elif defined(__NR_getegid)
# define __NR___syscall_getegid __NR_getegid
static inline _syscall0(int, __syscall_getegid);
gid_t getegid(void)
{
	return (__syscall_getegid());
}
#else
libc_hidden_proto(getgid)

gid_t getegid(void)
{
	return (getgid());
}
#endif
libc_hidden_def(getegid)
