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
.globl _errno

.globl _vfork
.type _vfork,@function
_vfork:
	l.addi	r11, r0, __NR_vfork
	l.sys	0x1			/* Make system call */
	 l.nop
	l.addi	r3, r0, 0xfffff000
	l.sfgtu	r11, r3			/* Check if failed */
	l.bnf	1f
	 l.sub	r3, r0, r11		/* Get errno value from return code */
	l.movhi	r4, hi(_errno)
	l.ori	r4, r4, lo(_errno)	/* Get address of errno */
	l.sw	0(r4), r3		/* Set errno */
	l.addi	r11, r0, -1		/* Return -1 from vfork */
1:
	l.jr	r9			/* All done, return */
	 l.nop

