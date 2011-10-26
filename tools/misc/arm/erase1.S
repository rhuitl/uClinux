
.text

start:
	mov	r1, #0x50000000
	mov	r2, #0x20
	orr	r2, r2, #0x2000
	strh	r2, [r1]
	mov	r2, #0xd0
	orr	r2, r2, #0xd000
	strh	r2, [r1]

	mov	r2, #0xff
	orr	r2, r2, #0xff00
	strh	r2, [r1]
