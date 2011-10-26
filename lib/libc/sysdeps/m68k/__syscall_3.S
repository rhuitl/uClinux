#define __CHECK_RETURN_ADDR
#include <sysdep.h>
.text
ENTRY(SYSCALL__3__COMMON)
SYSCALL__3__COMMON:
	PUSH_3
	MOVE_3
	trap _HASH 0
	POP_3
	bra SYSCALL__n_COMMON
