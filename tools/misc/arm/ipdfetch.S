
.text
.global _start

_start:
	mov	r1, #0x80000000		// UART2 base
	orr	r1, r1, #0x008d0000
	mov	r2, #0x07
	str	r2, [r1,#0x10]		/* 115200 baud */
	mov	r2, #0x00
	str	r2, [r1,#0xc]
	mov	r2, #0x60
	str	r2, [r1,#0x8]		/* 8,n,1 */
	mov	r2, #0x01
	str	r2, [r1,#014]		/* Enable UART engine */

	mov	r4, #0			// counter
	mov	r5, #0xc0000000		// address
	orr	r5, r5, #0x00001000
	mov	r3, #0x10		// RXEMPTY bit (in FR register)
1:
	ldr	r2, [r1,#0x18]
	tst	r2, r3
	bne	1b

	ldr	r2, [r1,#0]
	strb	r2, [r5]
	add	r5, r5, #1
	add	r4, r4, #1
	b	1b

