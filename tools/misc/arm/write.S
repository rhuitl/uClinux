
.text

start:
	mov	r1, #0x50000000
	mov	r2, #0x90
	orr	r2, r2, #0x9000
	strh	r2, [r1]

