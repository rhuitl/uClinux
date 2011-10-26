/* vi: set sw=4 ts=4: */
/*
 * pause() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#define __UCLIBC_HIDE_DEPRECATED__
#include <sys/syscall.h>
#include <unistd.h>

extern __typeof(pause) __libc_pause;
#ifdef __NR_pause
#define __NR___libc_pause __NR_pause
_syscall0(int, __libc_pause);
#else
#include <signal.h>
libc_hidden_proto(__sigpause)
libc_hidden_proto(sigblock)

int __libc_pause(void)
{
	return (__sigpause(sigblock(0), 0));
}
#endif
weak_alias(__libc_pause,pause)
