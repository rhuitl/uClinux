/*****************************************************************************/
/*
 *	boot.S -- startup code for H8S platforms.
 *	Copyright (C) 2003, David McCullough <davidm@snapgear.com>
 */
/*****************************************************************************/

.global __start
.global __vectors
.global _startimage
.global _nop
.extern _main

/*****************************************************************************/

	.h8300s
	.align 4
	.text
__vectors: /* redirect vectors via the internal RAM */
	jmp	__start
	jmp	__start
	.rept	128-2
	jmp	0x00ffbe00 + . - __vectors
	.endr

	/* put the boot args at a known location */
	.align 4
boot_args:
	.ascii	"console=ttySC2,38400\0"

	.align 4
__start:
	/*
	 * initial stack setup
	 */
	orc     #0xC0, ccr
	mov.l	#0x00FFBFF0, er7

	/*
	 * Get console going for early debug
	 */
	mov.l	#0xffff41, er3		/* MSTPCRL &= 0xf7 - enable module */
	mov.b	@er3, r2l
	and.b	#0xf7, r2l
	mov.b	r2l, @er3
	sub.l	er2, er2			/* SCSCR   =  0x00 */
	mov.b	r2l, @0xffff8a:32
	mov.l	#0xffff88, er3		/* SCSMR  &= ~0x03 */
	mov.b	@er3, r2l
	and.b	#0xfc, r2l
	mov.b   r2l, @(0,er3)
	sub.l	er2, er2			/* SCBRR   =  0x19 - 38400 */
	add.b	#0x19, r2l
	mov.b	r2l, @0xffff89:32
	/*
	 * delay 1 bit times
	 */
	sub.l	er2, er2
1:
	adds	#0x1, er2
	cmp.l	#0x270f, er2
	ble		1b
	/*
	 * enable RX/TX
	 */
	mov.b	#0x30, r2l			/* SCSCR   = 0x30 */
	mov.b	r2l, @0xffff8a:32

	mov.l	#header, er0
	jsr		dbg_string

	/*
	 * BSC setup
	 */
	mov.b	#0xff, r2l			/* ASTCR   = 0xff */
	mov.b	r2l, @0xfffec1:32
	mov.b	#0x27, r2l			/* WTCRAH  = 0x27 */
	mov.b	r2l, @0xfffec2:32
	mov.b	#0x77, r2l			/* WTCRAL  = 0x77 */
	mov.b	r2l, @0xfffec3:32
	mov.b	#0x71, r2l			/* WTCRBH  = 0x71 */
	mov.b	r2l, @0xfffec4:32
	mov.b	#0x00, r2l			/* RDNCR   = 0x00 */
	mov.b	r2l, @0xfffec6:32
	mov.b	#0x80, r2l			/* CSACRH  = 0x80 */
	mov.b	r2l, @0xfffec8:32
	mov.b	#0x80, r2l			/* CSACRL  = 0x80 */
	mov.b	r2l, @0xfffec9:32
	mov.b	#0xa0, r2l			/* BROMCRL = 0xa0 */
	mov.b	r2l, @0xfffecb:32
	mov.w	#0x0d04, r2			/* BCR     = 0x0d04 */
	mov.w	r2, @0xfffecc:32
	mov.b	#0x80, r2l			/* ABWCR   = 0x80 */
	mov.b	r2l, @0xfffec0:32
	mov.b	#0x22, r2l			/* WTCRBL  = 0x22 */
	mov.b	r2l, @0xfffec5:32
	mov.b	#0xa0, r2l			/* BROMCRH = 0xa0 */
	mov.b	r2l, @0xfffeca:32

	/*
	 * Port setup
	 */
	mov.b	#0x00, r2l			/* P3DR    = 0x00 */
	mov.b	r2l, @0xffff62:32
	mov.b	#0x30, r2l			/* P3DDR   = 0x30 */
	mov.b	r2l, @0xfffe22:32
	mov.b	#0x06, r2l			/* P3ODR   = 0x06 */
	mov.b	r2l, @0xfffe3c:32
	// mov.b	#0x0d, r2l			/* PFCR2   = 0x0D */
	mov.b	#0x01, r2l			/* PFCR2   = 0x01 */
	mov.b	r2l, @0xfffe34:32
	mov.b	#0xff, r2l			/* PADDR   = 0xff */
	mov.b	r2l, @0xfffe29:32
	mov.b	#0x0f, r2l			/* PGDDR   = 0x0f */
	mov.b	r2l, @0xfffe2f:32
	mov.b	#0x0f, r2l			/* PHDDR   = 0x0f */
	mov.b	r2l, @0xffff74:32
	mov.b	#0xfe,r2l			/* PFDDR   = 0xfe */
	mov.b	r2l, @0xfffe2e:32
	mov.b	#0xff,r2l			/* PFCR0   = 0xff */
	mov.b	r2l, @0xfffe32:32

	/*
	 * SDRAM setup
	 */
	mov.w	#0x9000, r2			/* DRACCR  = 0x9000 */
	mov.w	r2, @0xfffed2:32
	mov.w	#0x0188, r2			/* REFCR   = 0x0188 */
	mov.w	r2, @0xfffed4:32
	mov.b	#0xff, r2l			/* RTCOR   = 0xff */
	mov.b	r2l, @0xfffed7:32
	mov.b	#0xff, r2l			/* PADDR   = 0xff */
	mov.b	r2l, @0xfffe29:32
	mov.b	#0xff, r2l			/* PFCR1   = 0xff */
	mov.b	r2l, @0xfffe33:32
	mov.w	#0x85b4,r2			/* DRAMCR  = 0x85b4 */
	mov.w	r2, @0xfffed0:32
	mov.b	#0x00, r2l			/* SDRAM_CONTRL = 0 */
	mov.b	r2l, @0x400040:32
	mov.w	#0x84b4,r2			/* DRAMCR  = 0x84b4 */
	mov.w	r2, @0xfffed0:32

	/*
	 * Interrupt controller setup
	 */
	mov.w	#0x0000, r2			/* IER   = 0x0000 */
	mov.w	r2, @0xffff32:32
	mov.b	#0x04, r2l			/* INTCR = 0x04; */
	mov.b	r2l, @0xffff31:32
	mov.w	#0x0555, r2			/* ISCRL = 0x0555 */
	mov.w	r2, @0xfffe1c:32
	mov.w	#0xff3f, r2			/* ITSR  = 0xff3f */
	mov.w	r2, @0xfffe16:32

	/*
	 * copy kernel from ROM (256K) to RAM,  we don't know how big it
	 * is so copy 4Mb - 256K (slow I know)
	 */
	mov.l	#0x40000, er5
	mov.l	#0x400000, er6
1:
	mov.l	#0x8000, er4
	mov.b	#'.', r0l
	jsr		dbg_char
	eepmov.w
	cmp.l	#0x400000, er5
	bne		1b

	mov.b	#'\r', r0l
	jsr		dbg_char
	mov.b	#'\n', r0l
	jsr		dbg_char

	/*
	 * Copy the boot args
	 */
	mov.l	#boot_args, er5
	mov.l	#0x00bffe00, er6
	mov.l	#512, er4
	eepmov.w

	/*
	 * jump into kernel at start of RAM
	 */
	mov.l	#0x400000, er1
	jmp @er1

	.align 4
dbg_char:
	mov.l   #0xFFFF8C, er3
	mov.b   @er3, r2l
	bge dbg_char
	mov.b   r0l, @0xFFFF8B:32
	mov.b   @er3, r2l
	and.b   #0x7f, r2l
	mov.b   r2l, @er3
	rts

	.align 4
dbg_string:
	mov.l   er0, er1
1:
	mov.b	@er1+, r0l
	beq		2f
	jsr		dbg_char
	bra		1b
2:
	rts

header:
	.ascii	"Hitachi EDOSK2674 Simple Boot Loader\r\n"
	.ascii	"Copyright (C) 2003 David McCullough <davidm@snapgear.com>\r\n\0"

/****************************************************************************/
