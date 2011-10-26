/* vi: set sw=4 ts=4: */
/*
 * exit syscall for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <features.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

libc_hidden_proto(_exit)

#ifndef INLINE_SYSCALL
#define INLINE_SYSCALL(name, nr, args...) __syscall_exit (args)
#define __NR___syscall_exit __NR_exit
static inline _syscall1(void, __syscall_exit, int, status);
#endif

void attribute_noreturn _exit(int status)
{
	/* The loop is added only to keep gcc happy. */
	while(1)
		INLINE_SYSCALL(exit, 1, status);
}
libc_hidden_def(_exit)
