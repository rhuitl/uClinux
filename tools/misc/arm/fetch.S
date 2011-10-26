
.text
.global _start

_start:
	mov	r1, #0x03f00000		// UART base
	orr	r1, r1, #0x000fe000
	mov	r2, #0xd9		// 115200
	str	r2, [r1,#0x1c]
	mov	r2, #0x03		// 8,n,1
	str	r2, [r1,#0x0c]

	mov	r4, #0			// counter
	//mov	r5, #0x8000		// address
	mov	r3, #0x01
1:
	ldr	r2, [r1,#0x14]
	tst	r2, r3
	beq	1b

	ldr	r2, [r1,#0]
	strb	r2, [r5]
	add	r5, r5, #1
	add	r4, r4, #1
	b	1b

