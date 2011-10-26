/* vi: set sw=4 ts=4: */
/*
 * delete_module() for uClibc
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
int delete_module(const char *name);
#ifdef __NR_delete_module
_syscall1(int, delete_module, const char *, name);
#else
int delete_module(const char *name)
{
	__set_errno(ENOSYS);
	return -1;
}
#endif
