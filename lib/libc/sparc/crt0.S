/****************************************************************************/

/*
 *	crt0.S -- application start up code (for sparc)
 *
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com)
 */

/****************************************************************************/

.global	_start
.global environ

.text

	nop				/* filler */
	nop

_start:
	ld	[%o6 + 0x40], %o0	/* get argc */
	ld	[%o6 + 0x44], %o1	/* get argv */
	ld	[%o6 + 0x48], %o2	/* get env */

	call	main
	 nop				/* delay slot */

	/* o0 (return value) passed to exit call as arg */
	call	exit			/* libc exit call */
	 nop				/* delay slot */

	/* If that didn't kill us, do it the hard way */
__exit:
	mov	0, %o0			/* good exit status */
	mov	1, %g1			/* "exit" system call */
	ta	0x10			/* system call */
	 nop				/* delay slot */

/****************************************************************************/

.section .ctors,"aw"
.align 4
.global __CTOR_LIST__
__CTOR_LIST__:
	.long -1

.section .dtors,"aw"
.align 4
.global __DTOR_LIST__
__DTOR_LIST__:
	.long -1

/****************************************************************************/

.data
environ:
	.long 0

/****************************************************************************/
