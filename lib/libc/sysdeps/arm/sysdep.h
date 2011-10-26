/* Copyright (C) 1992 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#ifndef _LINUX_ARM_SYSDEP_H
#define _LINUX_ARM_SYSDEP_H 1

#include <sys/syscall.h>

/* For Linux we can use the system call table in the header file
	/usr/include/asm/unistd.h
   of the kernel.  But these symbols do not follow the SYS_* syntax
   so we have to redefine the `SYS_ify' macro here.  */
#undef SYS_ify
#define SWI_BASE  (0x900000)
#define SYS_ify(syscall_name)	(SWI_BASE+SYS_##syscall_name)


#ifdef __ASSEMBLER__

/* Linux uses a negative return value to indicate syscall errors,
   unlike most Unices, which use the condition codes' carry flag.

   Since version 2.1 the return value of a system call might be
   negative even if the call succeeded.  E.g., the `lseek' system call
   might return a large offset.  Therefore we must not anymore test
   for < 0, but test for a real error by making sure the value in R0
   is a real error number.  Linus said he will make sure the no syscall
   returns a value in -1 .. -4095 as a valid result so we can savely
   test with -4095.  */

#define SYMBOL_NAME(X) X
#define SYMBOL_NAME_LABEL(X) X##:
#define PLTJMP(n) n
#define C_SYMBOL_NAME(x) x
#define ALIGN 4
#define END(sym)

#define weak_alias(original, alias)	\
		.weak C_SYMBOL_NAME (alias);	\
		C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)




#define LOADREGS(cond, base, reglist...)\
		ldm##cond	base,reglist

#define RETINSTR(instr, regs...)\
				instr	regs


#define ret		RETINSTR(mov, pc, r14)
#define MOVE(a,b)	mov b,a


#define	ENTRY(name)							      \
		  .globl SYMBOL_NAME(name);						      \
		  .align ALIGN;								      \
		  SYMBOL_NAME_LABEL(name)




#undef	PSEUDO
#define	PSEUDO(name, syscall_name, args)				      \
		  .text;								      \
		  .type name,%function;					      \
		  ENTRY (name);								      \
		  DO_CALL (args, syscall_name);					      \
		  cmn r0, $4096;							      \
		  bhs __syscall_error

#undef	PSEUDO_END
#define	PSEUDO_END(name)						      \
	  SYSCALL_ERROR_HANDLER							      \
	  END (name)

#define SYSCALL_ERROR_HANDLER	/* Nothing here; code in sysdep.S is used.  */

/* Linux takes system call args in registers:
	syscall number	in the SWI instruction
	arg 1		r0
	arg 2		r1
	arg 3		r2
	arg 4		r3
	arg 5		r4	(this is different from the APCS convention)

   The compiler is going to form a call by coming here, through PSEUDO, with
   arguments
   	syscall number	in the DO_CALL macro
   	arg 1		r0
   	arg 2		r1
   	arg 3		r2
   	arg 4		r3
   	arg 5		[sp]

   We need to shuffle values between R4 and the stack so that the caller's
   R4 is not corrupted, and the kernel sees the right argument there.

*/

#undef	DO_CALL
#define DO_CALL(args, syscall_name)		\
			DOARGS_##args				\
			swi SYS_ify (syscall_name); 		\
			UNDOARGS_##args

#define DOARGS_0 /* nothing */
#define DOARGS_1 /* nothing */
#define DOARGS_2 /* nothing */
#define DOARGS_3 /* nothing */
#define DOARGS_4 /* nothing */
#define DOARGS_5 ldr ip, [sp]; str r4, [sp]; mov r4, ip;

#define UNDOARGS_0 /* nothing */
#define UNDOARGS_1 /* nothing */
#define UNDOARGS_2 /* nothing */
#define UNDOARGS_3 /* nothing */
#define UNDOARGS_4 /* nothing */
#define UNDOARGS_5 ldr r4, [sp];

#else /* not __ASSEMBLER__ */

/* Define a macro which expands into the inline wrapper code for a system
   call.  */
#undef INLINE_SYSCALL
#define INLINE_SYSCALL(name, nr, args...)			\
		({ unsigned int _sys_result;					\
			{								\
			register int _a1 asm ("a1");				\
			LOAD_ARGS_##nr (args)					\
			asm volatile ("swi	%1	@ syscall " #name	\
			: "=r" (_a1)				\
			: "i" (SYS_ify(name)) ASM_ARGS_##nr	\
			);					\
			_sys_result = _a1;					\
			}								\
			if (_sys_result >= (unsigned int) -4095)			\
			{							\
			__set_errno (-_sys_result);				\
			_sys_result = (unsigned int) -1;			\
			}							\
			(int) _sys_result; })

#define LOAD_ARGS_0()
#define ASM_ARGS_0
#define LOAD_ARGS_1(a1)				\
									_a1 = (int) (a1);				\
									LOAD_ARGS_0 ()
#define ASM_ARGS_1	ASM_ARGS_0, "r" (_a1)
#define LOAD_ARGS_2(a1, a2)			\
									register int _a2 asm ("a2") = (int) (a2);	\
									LOAD_ARGS_1 (a1)
#define ASM_ARGS_2	ASM_ARGS_1, "r" (_a2)
#define LOAD_ARGS_3(a1, a2, a3)			\
										register int _a3 asm ("a3") = (int) (a3);	\
										LOAD_ARGS_2 (a1, a2)
#define ASM_ARGS_3	ASM_ARGS_2, "r" (_a3)
#define LOAD_ARGS_4(a1, a2, a3, a4)		\
										register int _a4 asm ("a4") = (int) (a4);	\
										LOAD_ARGS_3 (a1, a2, a3)
#define ASM_ARGS_4	ASM_ARGS_3, "r" (_a4)
#define LOAD_ARGS_5(a1, a2, a3, a4, a5)		\
											register int _v1 asm ("v1") = (int) (a5);	\
											LOAD_ARGS_4 (a1, a2, a3, a4)
#define ASM_ARGS_5	ASM_ARGS_4, "r" (_v1)


#define weak_alias(name, aliasname) \
	extern __typeof (name) aliasname __attribute__ ((weak, alias (#name)));

/* This comes between the return type and function name in
   a function definition to make that definition weak.  */
#define weak_function __attribute__ ((weak))
#define weak_const_function __attribute__ ((weak, __const__))

extern int errno;

#define __set_errno(e) errno = e


#endif	/* __ASSEMBLER__ */


#define	SYSCALL__(name,args)		PSEUDO (name, name, args)
#define	SYSCALL(name,args)		PSEUDO (name, name, args)
#define	SYSCALL_RET(name,args)		PSEUDO (name, name, args); ret
#define	SYSCALL_RET_X(name,num,args)	PSEUDO (name, num, args); ret


#endif /* linux/arm/sysdep.h */
