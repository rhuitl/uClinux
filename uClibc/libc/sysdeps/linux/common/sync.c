/* vi: set sw=4 ts=4: */
/*
 * sync syscall for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <features.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef INLINE_SYSCALL
#define INLINE_SYSCALL(name, nr, args...) __syscall_sync (args)
#define __NR___syscall_sync __NR_sync 
static inline _syscall0(void, __syscall_sync);
#endif

void sync(void)
{
	INLINE_SYSCALL(sync, 0);
}

