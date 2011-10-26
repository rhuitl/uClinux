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

#include <sys/syscall.h>

#define SYMBOL_NAME(X) _##X
#define SYMBOL_NAME_LABEL(X) _##X##:
#define ALIGN 4

#define	ENTRY(name)							      \
  .global SYMBOL_NAME(name);						      \
  .align ALIGN;								      \
  SYMBOL_NAME_LABEL(name)

#define _HASH  #

/* In case of returning a memory address, negative values may not mean
   error.  Moreover, we have to copy the return value to register %a0,
   as those syscalls are normally declared to return a pointer.  */

#ifdef __CHECK_RETURN_ADDR
#define check_error(LAB)	cmp.l _HASH -4096, %d0; jls LAB
#define copy_ret		move.l %d0, %a0
#else
#define check_error(LAB)	tst.l %d0; jpl LAB
#define copy_ret		/* empty */
#endif

#define ERRNO_LOCATION SYMBOL_NAME(__errno_location)

#define PSEUDO(name, syscall_name, args)			\
  	.text;							\
  	ENTRY (name)                                            \
    	l.addi r11,r0,SYS_##syscall_name;			\
    	l.sys 1;						\
    	l.nop;							\
    	l.jr r9;						\
	l.nop

#define ret 							\
	l.jr r9;						\
	l.nop

#define	SYSCALL_RET(name,args)		PSEUDO(name, name, args)
#define	SYSCALL_RET_X(name,num,args)	PSEUDO(name, num, args)
