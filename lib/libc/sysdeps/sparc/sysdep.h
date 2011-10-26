/* Copyright (C) 2002, Greg Ungerer (gerg@snapgear.com)
   Copyright (C) 1992 Free Software Foundation, Inc.

Based on sysdep.h files from GNU glibc.

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

#ifndef _LINUX_SPARC_SYSDEP_H
#define _LINUX_SPARC_SYSDEP_H 1

#include <sys/syscall.h>


#ifdef __ASSEMBLER__

/*
 * Linux uses a negative return value to indicate syscall errors,
 * unlike most Unices, which use the condition codes' carry flag.
 *
 * Since version 2.1 the return value of a system call might be
 * negative even if the call succeeded.  E.g., the `lseek' system call
 * might return a large offset.  Therefore we must not anymore test
 * for < 0, but test for a real error by making sure the value in R0
 * is a real error number.  Linus said he will make sure the no syscall
 * returns a value in -1 .. -4095 as a valid result so we can savely
 * test with -4095.
 */
#define SYMBOL_NAME(X)		X
#define SYMBOL_NAME_LABEL(X)	X##:
#define ALIGN			4


#define	ENTRY(name)				\
	.globl SYMBOL_NAME(name) ;		\
	.align ALIGN ;				\
	SYMBOL_NAME_LABEL(name)

#undef	PSEUDO
#define	PSEUDO(name, syscall_name, args)	\
	.text ;					\
	.type	name,%function ;		\
	ENTRY (name)				\
	save	%sp, -112, %sp ;		\
	DOARGS_##args				\
	mov	SYS_##syscall_name, %g1 ;	\
	ta	0x10 ;				\
	set	-4096, %o1 ;			\
	cmp	%o0, %o1 ;			\
	bleu	1f ;				\
	 mov	%o0, %i0 ;			\
	set	errno, %g1 ;			\
	neg	%o0 ;				\
	st	%o0, [%g1] ;			\
	set	-1, %i0 ;			\
	1:					\
	ret ;					\
	 restore


/*
 *	Linux takes system call args in registers:
 *	syscall arg number   at the trap instruction
 *	  arg 1			o0
 *	  arg 2			o1
 *	  arg 3			o2
 *	  arg 4			o3
 *	  arg 5			o4
 */
#define DOARGS_0			\
	/* nothing */

#define DOARGS_1			\
	mov	%i0, %o0 ;

#define DOARGS_2			\
	mov	%i0, %o0 ;		\
	mov	%i1, %o1 ;

#define DOARGS_3			\
	mov	%i0, %o0 ;		\
	mov	%i1, %o1 ;		\
	mov	%i2, %o2 ;

#define DOARGS_4			\
	mov	%i0, %o0 ;		\
	mov	%i1, %o1 ;		\
	mov	%i2, %o2 ;		\
	mov	%i3, %o3 ;

#define DOARGS_5			\
	mov	%i0, %o0 ;		\
	mov	%i1, %o1 ;		\
	mov	%i2, %o2 ;		\
	mov	%i3, %o3 ;		\
	mov	%i4, %o4 ;

#endif /*__ASSEMBLER__*/

#define	SYSCALL_RET(name,args)		PSEUDO(name, name, args)
#define	SYSCALL_RET_X(name,num,args)	PSEUDO(name, num, args)

#endif /* sparc/sysdep.h */
