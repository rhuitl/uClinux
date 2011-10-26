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

#define SYMBOL_NAME(X) X
#define SYMBOL_NAME_LABEL(X) X##:
#define ALIGN 2

#define	ENTRY(name)							      \
  .globl SYMBOL_NAME(name);						      \
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

#define PSEUDO(name, syscall_name, args)                                      \
  .text;								      \
  ENTRY (name)                                                                \
    PUSH_##args 							      \
    movel _HASH SYS_##syscall_name,%d0;					      \
    MOVE_##args 							      \
    trap  _HASH 0;							      \
    check_error(1f);							      \
    negl  %d0;								      \
    movel %d0,%sp@-;							      \
    lea   ERRNO_LOCATION-.-8, %a0;					      \
    jsr  0(%pc, %a0);						      	      \
    movel %d0, %a0;							      \
    movel %sp@+,%a0@;							      \
    moveq _HASH -1,%d0;							      \
 1: copy_ret;								      \
    POP_##args

/* Linux takes system call arguments in registers:
	1: d1
	2: d2
	3: d3
	4: d4
	5: d5
 */

#define PUSH_0	/* No arguments to push.  */
#define PUSH_1	/* no need to restore d1  */
#define PUSH_2	movel %d2,%sp@-;
#if defined (CONFIG_COLDFIRE)
#define PUSH_3	subl #8,%sp; \
		movml %d2-%d3,%sp@;
#define PUSH_4	subl #12,%sp; \
		movml %d2-%d4,%sp@;
#define PUSH_5	subl #16,%sp; \
		movml %d2-%d5,%sp@;
#else
#define PUSH_3	movml %d2-%d3,%sp@-;
#define PUSH_4	movml %d2-%d4,%sp@-;
#define PUSH_5	movml %d2-%d5,%sp@-;
#endif

#define MOVE_0	/* No arguments to move.  */

#define MOVE_1	movl %sp@(4),%d1;
#define MOVE_2	movml %sp@(8),%d1-%d2;
#define MOVE_3	movml %sp@(12),%d1-%d3;
#define MOVE_4	movml %sp@(16),%d1-%d4;
#define MOVE_5	movml %sp@(20),%d1-%d5;

#define POP_0	/* No arguments to pop.  */
#define POP_1	/* didn't save d1        */
#define POP_2	movel %sp@+,%d2;
#if defined (CONFIG_COLDFIRE)
#define POP_3	movml %sp@,%d2-%d3; \
		addl #8,%sp
#define POP_4	movml %sp@,%d2-%d4; \
		addl #12,%sp
#define POP_5	movml %sp@,%d2-%d5; \
		addl #16,%sp
#else
#define POP_3	movml %sp@+,%d2-%d3;
#define POP_4	movml %sp@+,%d2-%d4;
#define POP_5	movml %sp@+,%d2-%d5;
#endif

#define ret rts

/* Short cut syscalls that skip the bulk of the code */
#define SYSCALL__X0(syscall_name, syscall_num)		\
  .text;						\
  ENTRY (syscall_name)					\
	movel _HASH SYS_##syscall_num,%d0;		\
	bra SYSCALL__0__COMMON

#define SYSCALL__X1(syscall_name, syscall_num)		\
  .text;						\
  ENTRY (syscall_name)					\
	movel _HASH SYS_##syscall_num,%d0;		\
	bra SYSCALL__1__COMMON

#define SYSCALL__X2(syscall_name, syscall_num)		\
  .text;						\
  ENTRY (syscall_name)					\
	movel _HASH SYS_##syscall_num,%d0;		\
	bra SYSCALL__2__COMMON

#define SYSCALL__X3(syscall_name, syscall_num)		\
  .text;						\
  ENTRY (syscall_name)					\
	movel _HASH SYS_##syscall_num,%d0;		\
	bra SYSCALL__3__COMMON

#define SYSCALL__X4(syscall_name, syscall_num)		\
  .text;						\
  ENTRY (syscall_name)					\
	movel _HASH SYS_##syscall_num,%d0;		\
	bra SYSCALL__4__COMMON

#define SYSCALL__X5(syscall_name, syscall_num)		\
  .text;						\
  ENTRY (syscall_name)					\
	movel _HASH SYS_##syscall_num,%d0;		\
	bra SYSCALL__5__COMMON

#define SYSCALL__0(syscall_name)	SYSCALL__X0(syscall_name, syscall_name)
#define SYSCALL__1(syscall_name)	SYSCALL__X1(syscall_name, syscall_name)
#define SYSCALL__2(syscall_name)	SYSCALL__X2(syscall_name, syscall_name)
#define SYSCALL__3(syscall_name)	SYSCALL__X3(syscall_name, syscall_name)
#define SYSCALL__4(syscall_name)	SYSCALL__X4(syscall_name, syscall_name)
#define SYSCALL__5(syscall_name)	SYSCALL__X5(syscall_name, syscall_name)

#define SYSCALL_RET(name,args)		SYSCALL__##args(name)
#define SYSCALL_RET_X(name,num,args)	SYSCALL__X##args(name,num)

/* The no return version for everybody */
#define	SYSCALL__(name,args)	PSEUDO (name, name, args)
#define	SYSCALL(name,args)	PSEUDO (name, name, args)
