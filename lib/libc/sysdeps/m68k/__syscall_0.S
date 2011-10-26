#define __CHECK_RETURN_ADDR
#include <sysdep.h>
.text
ENTRY(SYSCALL__0__COMMON)
SYSCALL__0__COMMON:
	PUSH_0
	MOVE_0
	trap _HASH 0
	POP_0
	bra SYSCALL__n_COMMON

