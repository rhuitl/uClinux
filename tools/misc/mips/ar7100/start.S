#include "mips.h"

#define	STACKSIZE	4096

.text
.set noreorder
.set mips1

.global __start
.type __start,@function

__start:
	lui	sp, %hi(stack+STACKSIZE-4)
	addiu	sp, sp, %lo(stack+STACKSIZE-4)

	jal	main
	 nop

forever:
	b	forever
	 nop

.comm stack,STACKSIZE,4

