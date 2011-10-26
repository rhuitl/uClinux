/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

libc_hidden_proto(wait4)

extern __typeof(waitpid) __libc_waitpid;
__pid_t __libc_waitpid(__pid_t pid, int *wait_stat, int options)
{
	return wait4(pid, wait_stat, options, NULL);
}
libc_hidden_proto(waitpid)
weak_alias(__libc_waitpid,waitpid)
libc_hidden_weak(waitpid)
