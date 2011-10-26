	.global	_start

	.bss
	.global environ
environ:
	.long 0

	.text
/* Moving start to after the nops ensures that no symbol ever exists at
 * location zero in the image.  However the program will still start
 * execution from zero effectively ignoring _start.
 */
/* _start: */
	nop
	nop
_start:

	/* %d5 hack for uClinux, see linux/include/asm-m68knommu/processor.h */
	movea.l %d5, %a5
	move.l 8(%sp), %d5
	move.l environ@GOT(%a5), %a0
	move.l %d5, (%a0)
	
	lea main-.-8, %a0
	jsr 0(%pc, %a0)

	move.l %d0,%sp@-
	lea exit-.-8, %a0
	jsr 0(%pc, %a0)

	/* If that didn't kill us, ... */
__exit:
	move.l %sp@+,%d1
	moveq #1,%d0 /* SYS_exit */
	trap #0

#if 0
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

#endif
