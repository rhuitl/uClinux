/* vi: set sw=4 ts=4: */
/*
 * ustat() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/ustat.h>
#include <sys/sysmacros.h>

#define __NR___syscall_ustat __NR_ustat
static inline _syscall2(int, __syscall_ustat,
		unsigned short int, kdev_t, struct ustat *, ubuf);

int ustat(dev_t dev, struct ustat *ubuf)
{
	/* We must convert the dev_t value to a __kernel_dev_t */
	__kernel_dev_t k_dev;

	k_dev = ((major(dev) & 0xff) << 8) | (minor(dev) & 0xff);
	return __syscall_ustat(k_dev, ubuf);
}
