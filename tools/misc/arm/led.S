
.text
.global _start

_start:
	ldr	r1, cs2
	ldr	r2, cs2val
	str	r2, [r1]	
cs2:
	.long	0xc4000008
cs2val:
	.long	0xbfff0003
