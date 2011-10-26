#define __CHECK_RETURN_ADDR
#include <sysdep.h>
.text
ENTRY(SYSCALL__5__COMMON)
SYSCALL__5__COMMON:
	PUSH_5
	MOVE_5
	trap _HASH 0
	POP_5
	bra SYSCALL__n_COMMON

