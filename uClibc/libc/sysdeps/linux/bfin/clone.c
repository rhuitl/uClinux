/*
 * libc/sysdeps/linux/bfin/clone.c -- `clone' syscall for linux/blackfin
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>

int
clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg, ...)
{
	register long rval = -1;

	if (fn && child_stack) {

#ifdef __BFIN_FDPIC__
	__asm__ __volatile__ (
			"r1 = %2;"
			"r0 = %3;"
			"P0 = %1;"
			"excpt 0;"	 /*Call sys_clone*/
			"%0  = r0;"
			"cc = r0 == 0;"
			"if !cc jump .Lxxx;"	/* if (rval != 0) skip to parent */
			"r0 = %4;"
			"p0 = %5;"
			"fp = 0;"
			"p1 = [p0];"
			"p3 = [p0 + 4];"
			"call (p1);"	/* Call cloned function */
			"p0 = %6;"
			"excpt 0;"	/* Call sys_exit */
			".Lxxx: nop;"
			: "=d" (rval)
			: "i" (__NR_clone), "a" (child_stack), "a" (flags), "a" (arg), "a" (fn), "i" (__NR_exit)
			: "CC", "R0", "R1", "P0");
#else
	__asm__ __volatile__ (
			"r1 = %2;"
			"r0 = %3;"
			"P0 = %1;"
			"excpt 0;"	 /*Call sys_clone*/
			"%0  = r0;"
			"cc = r0 == 0;"
			"if !cc jump .Lxxx;"	/* if (rval != 0) skip to parent */
			"r0 = %4;"
			"p0 = %5;"
			"fp = 0;"
			"call (p0);"	/* Call cloned function */
			"p0 = %6;"
			"excpt 0;"	/* Call sys_exit */
			".Lxxx: nop;"
			: "=d" (rval)
			: "i" (__NR_clone), "a" (child_stack), "a" (flags), "a" (arg), "a" (fn), "i" (__NR_exit)
			: "CC", "R0", "R1", "P0");
#endif

	} else {
		__set_errno(EINVAL);
	}

	return rval;
}
