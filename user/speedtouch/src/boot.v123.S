/*
*  ALCATEL SpeedTouch USB boot code for Speedtouch USB
*  Copyright (C) 2004 Edouard Gomez
*  
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*  
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*  
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
*  Author   : Ian
*  Creation : 2002
*  
*  This file contains all needed instructions to "boot" a Speedtouch USB
*  rev 1, 2 or 3 (but not 4). It's ARM code.
*
*  $Id: boot.v123.S,v 1.1 2004/02/15 14:48:05 edgomez Exp $
*/

/* The free code is obtained assembling this file, relocating it at base
 * address 0x00000000 and then making it a flat binary.
 * Next step is then to encapsulate the binary in a special file format
 * that specifies chunks and loading address to the usb mail box found in
 * the modem... more details available at:
 * http://ed.gomez.free.fr/speedtouch-info/
 *
 * A precompiled/encapsulated version is provided in boot.v123.bin
 */

/* ---------------------------------------------------------------------------
 * Copyright(C) 2002 Ian
 * -------------------------------------------------------------------------*/

.vector_tbl:	b	.setup
		b	.setup
		b	.setup
		b	.setup
		b	.setup
		b	.setup
		b	.irq
		b	.setup

.setup:		mov r0, #1
		mov r1, #0x1500000
		orr r1, r1, #0x64
		str r0, [r1]		/* timer of some sort. */

		mov r0, #0x4
		mov r1, #0x1400000
		orr r1, r1, #0x40
		str r0, [r1]

		mov r0, #0xd1		/* FIQ mode, interrupts off */
		msr CPSR_fc, r0
		mov sp, #16384		/* FIQ stack, starts 16K */

		mov r0, #0xd2		/* IRQ mode, interrupts off */
		msr CPSR_fc, r0
		mov sp, #0x3e00
		orr sp, sp, #0x70	/* IRQ stack, starts 0x3e70 */

		mov r0, #0xd3		/* Supervisor mode, ints off */
		msr CPSR_fc, r0
		mov sp, #0x3c00
		orr sp, sp, #0xe0	/* Supervisor stack, starts 0x3ce0 */


		mov r0, #0x8c000000
		add r0, r0, #8
		mov r1, #0x39
		str r1, [r0]

		mvn	r1, #95
		mvn	r3, #93
		mvn	r5, #92
		mvn	r7, #91
		mov	r2, #0x84000
		orr	r2, r2, #0x010
		mov	r0, #0x4000
		orr	r4, r0, #0x020
		orr	r6, r0, #0xe30
		str	r1, [r0]
		str	r3, [r2]
		str	r5, [r4]
		str	r5, [r4]
		str	r5, [r4]
		str	r5, [r4]
		str	r5, [r4]
		str	r5, [r4]
		str	r5, [r4]
		str	r5, [r4]
		str	r7, [r6] 

		mov r0, #0x8c000000
                add r0, r0, #8
                mov r1, #0xf4
                str r1, [r0]

		mov r0, #0xa0000000
		mov r1, #0x8000
		orr r1, r1, #0x15
		str r1, [r0]

		mov r1, #1
		mov r0, #0x90000000
		orr r0, r0, #0x20
		str r1, [r0]
		mov r0, #0xa4000000
		orr r0, r0, #0x20
		str r1, [r0]

.clear_mem:	mov r0, #0x200000
		mov r1, #0
1:		cmp r0, #16384
		str r1, [r0], #-4
		bgt 1b

.write_table:	mov r0, #0
		mov r1, #0x1fc000
		mov r3, #0xc10
		orr r3, r3, #0xe

1:		orr r2, r3, r0, lsl #20
		add r0, r0, #1
		str r2, [r1], #4
		cmp r0, #20
		blt 1b

		mov r3, #0xc00
		orr r3, r3, #0x2
1:		orr r2, r3, r0, lsl #20
                add r0, r0, #1
                str r2, [r1], #4
                cmp r0, #24
                blt 1b

		mov r3, #0xc10
                orr r3, r3, #0xe
1:              orr r2, r3, r0, lsl #20
                add r0, r0, #1
                str r2, [r1], #4
                cmp r0, #64
                blt 1b

		mov r3, #0xc00
                orr r3, r3, #0x2
1:              orr r2, r3, r0, lsl #20
                add r0, r0, #1
                str r2, [r1], #4
                cmp r0, #4096
                blt 1b


.finish_setup:	mov r0, #0x1fc000
		mov r4, #3
		mcr     15, 0, r0, cr2, cr0
		mcr     15, 0, r4, cr3, cr0
		mcr     15, 0, r0, cr7, cr0
		mcr     15, 0, r0, cr5, cr0
		mov r0, #61
		mcr     15, 0, r0, cr1, cr0

		mov r0, #0x53
		msr	CPSR_fc, r0   /* supervisor mode, IRQs on, FIQs off */

		mov r1, #0x4000
		orr r1, r1, #0x85
		mov r0, #0x84000000
		str r1, [r0]
		mov r1, #0x10
		mov r0, #0x80000008
		str r1, [r0]


/* start of the main code loop
 * r7 = USB base
 * r4 = temp
 */

		mov r7, #0x4000000
.packet_wait:	ldrb	r0, [r7, #2]
		subs	r0, r0, #1
		bne	.packet_wait	/* wait for non 1 event */
		ldrb	r0, [r7, #0]	/* packet 'reason code' */
		sub	r0, r0, #0x11

		/* get 1 word (load / exec address) */
		ldrb	r1, [r7, #11]
		ldrb	r4, [r7, #10]
		orr	r1, r4, r1, lsl #8
		ldrb	r4, [r7, #9]
		orr	r1, r4, r1, lsl #8
		ldrb	r4, [r7, #8]
		orr	r1, r4, r1, lsl #8

		/* Codes: 1 - upload (to modem)
		          3 - exec */
		cmp	r0, #3
		beq	.bootstrap
		cmp	r0, #1
		beq	1f
		mov	r0, #96		/* bad reason code */
		b	.ack
	
		/* Get packet size (16 bit word) */	
1:		ldrb	r2, [r7, #13]
		ldrb	r4, [r7, #12]
		orrs	r2, r4, r2, lsl #8
	
		beq	.bad_size	/* size == 0 - complain */
		mov 	r4, #0x1f0
		orr	r4, r4, #2
		cmp	r2, r4
		bgt	.bad_size	/* size > 0x1f2 - complain */

		add	r3, r7, #0x0e	/* data offset */

		/* Get data */
1:		subs	r2, r2, #1
		ldrb	r4, [r3, r2]
		strb	r4, [r1, r2]
		bne	1b

		/* set 'reset timeout' to 10 seconds */
		mov	r3, #20
		str	r3, rst_timeout
	
		mov	r0, #101		/* block received OK */
		b	.ack
		
.bad_size:	mov	r0, #102		/* Error: bad packet size */
.ack:		strb	r0, [r7, #1]		/* send ack. */
		b	.packet_wait		/* loop for more */


/* IRQ handler.
 * flashes LEDs. keeps board from resetting.
 * resets after small inactivity delay
 */

.irq:		sub	lr, lr, #4
		stmdb	sp!, {lr}
		mrs	lr, SPSR
		stmdb	sp!, {r0, r1, r2, lr}
/* flash LEDs */
		ldr	r0, led_stat   /* get LED status */
		eor	r0, r0, #1 /* toggle LED */
		str	r0, led_stat   /* store new status */
		cmp	r0, #0
		ldreq	r1, led_col	/* led colour */
		ldrne	r1, led_col_a   /* led alt colour */
		mov	r2, #0x1500000
		orr	r2, r2, #0x58
		str	r1, [r2]      /* set LEDs */

		mov	r0, #1
		mov	r1, #0x1500000
		orr     r1, r1, #0x64
		str	r0, [r1]            /* reset 'watchdog' timer? */

/* Time out if no data for a while */
		ldr	r0, rst_timeout
		sub	r0, r0, #1   /* timeout counter. see the main loop. */
		str	r0, rst_timeout
		cmp	r0, #0x0     /* if counter > 0 then */
		bne	1f           /* Dont reset the modem */
		mov	r0, #0xc300  /* otherwise... */
		orr	r0, r0, #0x70
		mov	r1, #0x1500000
		orr	r1, r1, #0x60
		str	r0, [r1]     /* reset modem! */

1:		mov	r2, #0x84000000 /* no idea */
		orr	r2, r2, #0x04
		ldr	r1, [r2]
		ldmia	sp!, {r0, r1, r2, lr}
		msr	SPSR_fc, lr
		ldmia	sp!, {pc}^

/* Bootstrap code
 * r1 = bootstrap address
 */

.bootstrap:	mov r0, #0xd3		/* Disable IRQs */
		msrnv CPSR_fc, r0	/* well, actually, dont 'cos it'll reset */
		mov	r0, #0xffffffff
		str	r0, rst_timeout
		/* end debug */
		mov     pc, r1          /* execute at <address> */

		
/* Useful constants */	
led_stat:	.word	0x0  /* LED colour status 0 = on, 1 = off */
rst_timeout:	.word	120  /* timeout counter */
led_col:	.word   0xd  /* LED colour setting. 0xd = green */
led_col_a:	.word   0xe  /* LED colour setting. 0xd = green */
