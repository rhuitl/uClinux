/* vi: set sw=4 ts=4: */
/*
 * getppid() for uClibc
 *
 * Copyright (C) 2000-2006 by Erik Andersen <andersen@codepoet.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#ifdef	__NR_getppid
_syscall0(pid_t, getppid);
#else
libc_hidden_proto(getpid)
pid_t getppid(void)
{
	return getpid();
}
#endif
