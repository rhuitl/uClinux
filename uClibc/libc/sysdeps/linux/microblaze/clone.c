/*
 * libc/sysdeps/linux/microblaze/clone.c -- `clone' syscall for linux/microblaze
 *
 *  Copyright (C) 2003     John Williams <jwilliams@itee.uq.edu.au>
 *  Copyright (C) 2002,03  NEC Electronics Corporation
 *  Copyright (C) 2002,03  Miles Bader <miles@gnu.org>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License.  See the file COPYING.LIB in the main
 * directory of this archive for more details.
 *
 * Written by Miles Bader <miles@gnu.org>
 * Microblaze port by John Williams
 */

#include <errno.h>
#include <sys/syscall.h>

int
clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg)
{
  register unsigned long rval = -EINVAL;

  if (fn && child_stack)
    {
      register unsigned long arg0;
      register unsigned long arg1;

      /* Clone this thread.  */
      arg0 = flags;
      arg1 = (unsigned long)child_stack;
      asm volatile (	"addik	r12, r0, %1	\n\t"
			"addk	r5, r0, %2	\n\t"
			"addk	r6, r0, %3	\n\t"
			"brki	r14, 0x08	\n\t"
			"addk	%0, r3, r0	\n\t"
		    : "=r" (rval)
		    : "i" (__NR_clone), "r" (arg0), "r" (arg1)
		    : "r3", "r5", "r6", "r12", "r14", "cc");

      if (rval == 0)
	/* In child thread, call FN and exit.  */
	{
	  arg0 = (*fn) (arg);
	  asm volatile ("addik	r12, r0, %1	\n\t"
			"addk	r5, r0, %2	\n\t"
			"brki	r14, 0x08	\n\t"
			"addk	%0, r0, r3	\n\t"
			: "=r" (rval)
			: "i" (__NR_exit), "r" (arg0)
			: "r3", "r5", "r12", "r14", "cc");
	}
    }

  __syscall_return (int, rval);
}
