/* vi: set sw=4 ts=4: */
/*
 * mknod() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

libc_hidden_proto(mknod)

#define __NR___syscall_mknod __NR_mknod
static inline _syscall3(int, __syscall_mknod, const char *, path,
		__kernel_mode_t, mode, __kernel_dev_t, dev);

int mknod(const char *path, mode_t mode, dev_t dev)
{
	/* We must convert the dev_t value to a __kernel_dev_t */
	__kernel_dev_t k_dev;

	k_dev = ((major(dev) & 0xff) << 8) | (minor(dev) & 0xff);
	return __syscall_mknod(path, mode, k_dev);
}
libc_hidden_def(mknod)
