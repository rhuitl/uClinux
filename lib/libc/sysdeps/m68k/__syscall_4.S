#define __CHECK_RETURN_ADDR
#include <sysdep.h>
.text
ENTRY(SYSCALL__4__COMMON)
SYSCALL__4__COMMON:
	PUSH_4
	MOVE_4
	trap _HASH 0
	POP_4
	bra SYSCALL__n_COMMON
