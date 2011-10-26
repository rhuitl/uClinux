/* vi: set sw=4 ts=4: */
/*
 * stat() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

/* need to hide the 64bit prototype or the strong_alias()
 * will fail when __NR_stat64 doesnt exist */
#define stat64 __hidestat64

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include "xstatconv.h"

#undef stat64

libc_hidden_proto(stat)

#define __NR___syscall_stat __NR_stat
#undef stat
static inline _syscall2(int, __syscall_stat,
		const char *, file_name, struct kernel_stat *, buf);

int stat(const char *file_name, struct stat *buf)
{
	int result;
	struct kernel_stat kbuf;

	result = __syscall_stat(file_name, &kbuf);
	if (result == 0) {
		__xstat_conv(&kbuf, buf);
	}
	return result;
}
libc_hidden_def(stat)

#if ! defined __NR_stat64 && defined __UCLIBC_HAS_LFS__
extern __typeof(stat) stat64;
libc_hidden_proto(stat64)
strong_alias(stat,stat64)
libc_hidden_def(stat64)
#endif
