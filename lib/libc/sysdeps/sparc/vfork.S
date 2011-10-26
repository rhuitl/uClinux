/*
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com)
 *
 *	This function is written as if an optermized leaf node function.
 *	It makes no use of the stack at all, and does not create its
 *	own stack frame with save/restore.
 */

#include <asm/unistd.h>

#ifndef __NR_vfork
#define __NR_vfork __NR_fork /* uClinux-2.0 only has fork which is vfork */
#endif

.text
.align 4
.globl errno

.globl vfork
.type vfork,@function
vfork:
	mov	__NR_vfork, %g1
	ta	0x10			/* Make system call */
	mov	-4096, %o1
	cmp	%o0, %o1		/* Check if failed */
	bleu	1f
	 nop
	set	errno, %g1		/* Get address of errno
	neg	%o0			/* Get errno value from return value */
	st	%o0, [%g1]		/* Set errno */
	set	-1, %o0			/* Return -1 from vfork */
1:
	retl				/* All done, return */
	 nop

