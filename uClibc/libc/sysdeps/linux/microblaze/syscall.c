/*
 * libc/sysdeps/linux/microblaze/syscall.c -- generic syscall function for linux/microblaze
 *
 *  Copyright (C) 2003  John Williams <jwilliams@itee.uq.edu.au>
 *  Copyright (C) 2002  NEC Corporation
 *  Copyright (C) 2002  Miles Bader <miles@gnu.org>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License.  See the file COPYING.LIB in the main
 * directory of this archive for more details.
 * 
 * Written by Miles Bader <miles@gnu.org>
 */

#include <errno.h>
#include <sys/syscall.h>

typedef unsigned long arg_t;

/* Invoke `system call' NUM, passing it the remaining arguments.
   This is completely system-dependent, and not often useful.  */
long
syscall (long num, arg_t a1, arg_t a2, arg_t a3, arg_t a4, arg_t a5, arg_t a6)
{
  /* We don't know how many arguments are valid, so A5 and A6 are fetched
     off the stack even for (the majority of) system calls with fewer
     arguments; hopefully this won't cause any problems.  A1-A4 are in
     registers, so they're OK.  */
  register unsigned long ret;

  asm (	"addk	r5, r0, %2	\n\t"
	"addk	r6, r0, %3	\n\t"
	"addk	r7, r0, %4	\n\t"
	"addk	r8, r0, %5	\n\t"
	"addk	r9, r0, %6	\n\t"
	"addk	r10,r0, %7	\n\t"
	"addk	r12,r0, %1	\n\t"
	"brki	r14, 0x08	\n\t"
	"addk	%0, r0, r3	\n\t"
       : "=r" (ret)
       : "r" (syscall), "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5),
		"r" (a6)
       : "r3", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "r14", "cc");
	
  __syscall_return (long, ret);
}
