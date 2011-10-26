
.text

start:
	mov	r1, #0xc4000000
	ldr	r2, [r1]
	orr	r2, r2, #0x02
	str	r2, [r1]

