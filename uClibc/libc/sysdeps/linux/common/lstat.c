/* vi: set sw=4 ts=4: */
/*
 * lstat() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

/* need to hide the 64bit prototype or the strong_alias()
 * will fail when __NR_lstat64 doesnt exist */
#define lstat64 __hidelstat64

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include "xstatconv.h"

#undef lstat64

libc_hidden_proto(lstat)

#define __NR___syscall_lstat __NR_lstat
static inline _syscall2(int, __syscall_lstat,
		const char *, file_name, struct kernel_stat *, buf);

int lstat(const char *file_name, struct stat *buf)
{
	int result;
	struct kernel_stat kbuf;

	result = __syscall_lstat(file_name, &kbuf);
	if (result == 0) {
		__xstat_conv(&kbuf, buf);
	}
	return result;
}
libc_hidden_def(lstat)

#if ! defined __NR_lstat64 && defined __UCLIBC_HAS_LFS__
extern __typeof(lstat) lstat64;
libc_hidden_proto(lstat64)
strong_alias(lstat,lstat64)
libc_hidden_def(lstat64)
#endif
