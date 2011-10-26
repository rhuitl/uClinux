#define __CHECK_RETURN_ADDR
#include <sysdep.h>
.text
ENTRY(SYSCALL__2__COMMON)
SYSCALL__2__COMMON:
	PUSH_2
	MOVE_2
	trap _HASH 0
	POP_2
	bra SYSCALL__n_COMMON
