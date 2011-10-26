#define __CHECK_RETURN_ADDR
#include <sysdep.h>
.text
ENTRY(syscall)
syscall:
	subl	#16, %sp
	movml	%d2-%d5, %sp@
	movml	%sp@(24), %d0-%d5
	trap 	#0
	movml	%sp@, %d2-%d5
	addl	#16, %sp
	bra SYSCALL__n_COMMON

