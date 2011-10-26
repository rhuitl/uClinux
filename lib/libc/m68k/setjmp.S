
/* Copyright (C) 2002, David McCullough <davidm@snapgear.com> */
/* This file is released under the LGPL, any version you like */

#define _ASM
#include <jmp_buf.h>

.global setjmp
.global longjmp

setjmp:
	moveal	%sp@(4), %a0
	movel	%sp@(0), %a0@(JB_PC)
	moveml	%d2-%d7/%a2-%a7, %a0@(JB_REGS)
#ifdef M68881
	fmovemx	%fp2-%fp7, %a0@(JB_FPREGS)
#endif
	clrl	%d0
	rts

longjmp:
	moveal	%sp@(4),%a0
	movel	%sp@(8),%d0
	bne		1f
	movel	#1,%d0
1:
	moveml	%a0@(JB_REGS), %d2-%d7/%a2-%a7
#ifdef M68881
	fmovemx	%a0@(JB_FPREGS), %fp2-%fp7
#endif
	movel	%a0@(JB_PC),%sp@
	rts

