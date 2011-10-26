
.text

start:
	mov	r1, #0x50000000
	orr	r1, r1, #0x00020000
	mov	r2, #0x60
	strb	r2, [r1]
	mov	r2, #0xd0
	strb	r2, [r1]

	mov	r2, #0xff
	strb	r2, [r1]
