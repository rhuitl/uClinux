#include <features.h>

	.file	"crti.S"
	.text
	
	.section .init
	.hidden  _init
	.align 1
	.global	_init
	.type	_init, @function
_init:
	mov.l	r12,@-r15
	mov.l	r14,@-r15
	sts.l	pr,@-r15
#ifndef __HAVE_SHARED__
	mova	.L6,r0
	mov.l	.L6,r12
	add	r0,r12
#endif	
	mov	r15,r14
	bra	1f
	nop
	.align 2
#ifndef __HAVE_SHARED__
.L6:
	.long	_GLOBAL_OFFSET_TABLE_
#endif
1:
	
	.section .fini
	.hidden  _fini
	.align 1
	.global	_fini
	.type	_fini, @function
_fini:
	mov.l	r12,@-r15
	mov.l	r14,@-r15
	sts.l	pr,@-r15
	mov	r15,r14
#ifndef __HAVE_SHARED__
	mov.l	.L11,r12
	mova	.L11,r0
	add	r0,r12
#endif	

	bra	1f
	nop
	.align 2
#ifndef __HAVE_SHARED__
.L11:
	.long	_GLOBAL_OFFSET_TABLE_
#endif
1:
	
	.ident	"GCC: (GNU) 3.3.2"
