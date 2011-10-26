#define __CHECK_RETURN_ADDR
#include <sysdep.h>
.text
.globl SYSCALL__n_COMMON
ENTRY(SYSCALL__1__COMMON)
SYSCALL__1__COMMON:
	PUSH_1
	MOVE_1
	trap _HASH 0
	POP_1
SYSCALL__n_COMMON:
	check_error(1f)
	negl  %d0
	movel %d0,%sp@-
	lea   ERRNO_LOCATION-.-8, %a0
	jsr  0(%pc, %a0)
	movel %d0, %a0
	movel %sp@+,%a0@
	moveq _HASH -1,%d0;
1:	copy_ret
	rts

