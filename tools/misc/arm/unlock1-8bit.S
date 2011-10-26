
.text

start:
	mov	r1, #0x50000000
	mov	r2, #0x60
	strb	r2, [r1]
	mov	r2, #0xd0
	strb	r2, [r1]

	mov	r2, #0xff
	strb	r2, [r1]
