#include "mips.h"

#define	STACKSIZE	4096

.text
.set noreorder
.set mips64

.global __start
.type __start,@function

__start:
	lui	sp, %hi(stack+STACKSIZE-8)
	addiu	sp, sp, %lo(stack+STACKSIZE-8)

	mfc0	t1, $12,0		/* COP0_STATUS_REG */
	li	v0, 0xe0		/* enable 64bit CSR access mode */
	or	v0, v0, t1
	mtc0	v0, $12,0		/* COP0_STATUS_REG */
	nop

	jal	main
	 nop

forever:
	b	forever
	 nop

.comm stack,STACKSIZE,8

