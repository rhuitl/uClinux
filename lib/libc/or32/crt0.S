/****************************************************************************/

/*
 *	crt0.S -- application start up code (for OR1k)
 *
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com)
 */

/****************************************************************************/

.global	_start
.global _environ

.text

	l.nop				/* filler */
	l.nop

_start:
	l.lwz	r3, 0(r1)		/* get argc */
	l.lwz	r4, 4(r1)		/* get argv */
	l.lwz	r5, 8(r1)		/* get env */

	l.jal	_main
	 l.nop				/* delay slot */

	l.add	r3, r0, r11		/* return value is exit status */
	l.jal	_exit			/* libc exit call */
	 l.nop				/* delay slot */

	/* If that didn't kill us, do it the hard way */
__exit:
	l.add	r3, r0, r0		/* good exit status */
	l.addi	r11, r0, 0x1		/* "exit" system call number */
	l.sys	0x1
	 l.nop				/* delay slot */

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
_environ:
	.long 0

/****************************************************************************/
