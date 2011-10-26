/* longjmp for ARM.
   Copyright (C) 1997, 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <features.h>
#define _SETJMP_H
#define _ASM
#include <bits/setjmp.h>


.global __longjmp
.type __longjmp,%function
.align 2
__longjmp:
	mov	ip, r0		/* save jmp_buf pointer */
	
	movs	r0, r1		/* get the return value in place */
	moveq	r0, #1		/* can't let setjmp() return zero! */

	ldmia     ip!,  {v1-v6, sl, fp, sp, lr}

#if defined __UCLIBC_HAS_FLOATS__ && ! defined __UCLIBC_HAS_SOFT_FLOAT__
#ifdef __VFP_FP__
	/* Restore the VFP registers.  */
	/* Following instruction is fldmiax ip!, {d8-d15}.  */
	ldc	p11, cr8, [r12], #68
	/* Restore the floating-point status register.  */
	ldr     r1, [ip], #4
	/* Following instruction is fmxr fpscr, r1.  */
	mcr	p10, 7, r1, cr1, cr0, 0
# elif defined __MAVERICK__
	cfldrd	mvd4,  [ip], #8 ; nop
	cfldrd	mvd5,  [ip], #8 ; nop
	cfldrd	mvd6,  [ip], #8 ; nop
	cfldrd	mvd7,  [ip], #8 ; nop
	cfldrd	mvd8,  [ip], #8 ; nop
	cfldrd	mvd9,  [ip], #8 ; nop
	cfldrd	mvd10, [ip], #8 ; nop
	cfldrd	mvd11, [ip], #8 ; nop
	cfldrd	mvd12, [ip], #8 ; nop
	cfldrd	mvd13, [ip], #8 ; nop
	cfldrd	mvd14, [ip], #8 ; nop
	cfldrd	mvd15, [ip], #8
# else
	lfmfd	f4, 4, [ip] !	/* load the floating point regs */
# endif
#endif	
#ifdef __IWMMXT__
	/* Restore the call-preserved iWMMXt registers.  */
	/* Following instructions are wldrd wr10, [ip], #8 (etc.)  */
	ldcl	p1, cr10, [r12], #8
	ldcl	p1, cr11, [r12], #8
	ldcl	p1, cr12, [r12], #8
	ldcl	p1, cr13, [r12], #8
	ldcl	p1, cr14, [r12], #8
	ldcl	p1, cr15, [r12], #8
#endif

#if defined(__USE_BX__)
	bx	lr
#else
	mov pc, lr
#endif

.size __longjmp,.-__longjmp
libc_hidden_def(__longjmp)
