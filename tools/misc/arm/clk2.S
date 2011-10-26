
.text

clk2:
	mov	r1, #0x80000000
	orr	r1, r1, #0x00930000
	ldr	r0, clk2v
	str	r0, [r1,#0x24]
	nop
	nop
	nop
	nop
	nop

clk2v:	.long	0x300dc317

