
.text

start:
	mov	r1, #0xc4000000
	orr	r1, r1, #0x20
	ldr	r2, [r1]
	and	r2, r2, #0x7fffffff
	str	r2, [r1]

