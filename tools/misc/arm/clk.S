
.text

clk:
	mov	r1, #0x80000000
	orr	r1, r1, #0x00930000
	ldr	r0, clk1v
	str	r0, [r1,#0x20]
	nop
	nop
	nop
	nop
	nop

clk1v:	.long	0x02a4e39e

