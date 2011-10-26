/* vi: set sw=4 ts=4: */
/*
 * _sysctl() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
/* psm: including sys/sysctl.h would depend on kernel headers */
extern int sysctl (int *__name, int __nlen, void *__oldval,
		   size_t *__oldlenp, void *__newval, size_t __newlen) __THROW;

struct __sysctl_args {
	int *name;
	int nlen;
	void *oldval;
	size_t *oldlenp;
	void *newval;
	size_t newlen;
	unsigned long __unused[4];
};

static inline
_syscall1(int, _sysctl, struct __sysctl_args *, args);

int sysctl(int *name, int nlen, void *oldval, size_t * oldlenp,
		   void *newval, size_t newlen)
{
	struct __sysctl_args args = {
	  name:name,
	  nlen:nlen,
	  oldval:oldval,
	  oldlenp:oldlenp,
	  newval:newval,
	  newlen:newlen
	};

	return _sysctl(&args);
}
