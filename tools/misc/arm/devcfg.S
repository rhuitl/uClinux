
.text

devcfg:
	mov	r1, #0x80000000
	orr	r1, r1, #0x00930000
	mov	r0, #0xaa
	str	r0, [r1,#0xc0]
	mov	r0, #0x00140000
	str	r0, [r1,#0x80]
	nop
	nop

