/* Copyright (C) 1996, 1997, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ralf Baechle <ralf@gnu.ai.mit.edu>, 1996.

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

/* clone() is even more special than fork() as it mucks with stacks
   and invokes a function in the right context after its all over.  */

#include <features.h>
#include <asm/unistd.h>
#include <sys/regdef.h>
#define _ERRNO_H	1
#include <bits/errno.h>
#include <sys/asm.h>

/* int clone(int (*fn)(void *arg), void *child_stack, int flags, void *arg) */

	.text
.globl   clone ;
	.align       2;
	.type         clone,@function;
	.ent        clone, 0;
	
clone:
	.frame	    sp, 4*SZREG, sp
#ifdef __PIC__
#if _MIPS_SIM == _MIPS_SIM_ABI32
	.set		noreorder
	.cpload		$25
	.set		reorder
	subu		sp,32
	.cprestore	16
#else	/* N32 */
	PTR_SUBU	sp,32	/* fn, arg, gp, pad */
	.cpsetup	$25, 16, clone
#endif	/* N32 */
#else
	subu		sp,32
#endif


	/* Sanity check arguments.  */
	li		v0,EINVAL
	beqz		a0,error	/* No NULL function pointers.  */
	beqz		a1,error	/* No NULL stack pointers.  */

#if _MIPS_SIM != _MIPS_SIM_ABI32
	and		a1,~(16-1)	/* force alignment */
#endif
	PTR_SUBU	a1,32		/* Reserve argument save space.  */
	PTR_S		a0,0(a1)	/* Save function pointer.  */
	PTR_S		a3,PTRSIZE(a1)	/* Save argument pointer.  */


	/* Do the system call */
	move		a0,a2
	li		v0,__NR_clone
	syscall

	bnez		a3,error
	beqz		v0,__thread_start

	/* Successful return from the parent */
#if _MIPS_SIM != _MIPS_SIM_ABI32
	.cpreturn
#endif
	PTR_ADDU	sp,32
	j $31  ; nop

	/* Something bad happened -- no child created */
error:
#if _MIPS_SIM != _MIPS_SIM_ABI32
	.cpreturn
#endif
	PTR_ADDU	sp,32

	/* uClibc change -- start */
	move		a0,v0		/* Pass return val to C function. */
	/* uClibc change -- stop */

#ifdef __PIC__
	PTR_LA		t9,__syscall_error
	jr		t9
#else
	j		__syscall_error
#endif
	.end  clone

/* Load up the arguments to the function.  Put this block of code in
   its own function so that we can terminate the stack trace with our
   debug info.  */

.globl  __thread_start;
	.align 2;
	.ent  __thread_start, 0;

__thread_start:
#if _MIPS_SIM == _MIPS_SIM_ABI32
	/* cp is already loaded.  */
	.cprestore	16
#endif
	/* The stackframe has been created on entry of clone().  */
	/* Restore the arg for user's function.  */
	PTR_L		t9,0(sp)	/* Function pointer.  */
	PTR_L		a0,PTRSIZE(sp)	/* Argument pointer.  */

	/* Call the user's function.  */
	jal		t9

	/* Call _exit rather than doing it inline for breakpoint purposes.  */
	move		a0,v0
	jal		HIDDEN_JUMPTARGET(_exit)
	.end  __thread_start
