/* vi: set sw=4 ts=4: */
/*
 * umount() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/mount.h>

/* arch provides umount() syscall */
#ifdef __NR_umount

_syscall1(int, umount, const char *, specialfile);

/* arch provides umount2() syscall */
#elif defined __NR_umount2

# define __NR___syscall_umount2 __NR_umount2
static inline _syscall2(int, __syscall_umount2, const char *, special_file, int, flags);

int umount(const char *special_file)
{
	return (__syscall_umount2(special_file, 0));
}

/* arch doesn't provide any umount syscall !? */
#else

int umount(const char *special_file)
{
	__set_errno(ENOSYS);
	return -1;
}

#endif
