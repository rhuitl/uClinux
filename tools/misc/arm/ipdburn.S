
.text
.global _start

#
#	During operation the following registers are set to:
#
#	r1  ==  flash address
#	r5  ==  memory address of image to program
#	r6  ==  memory address of end of image to program

_start:
	mov	r1, #0
	mov	r5, #0xc0000000
	orr	r5, r5, #0x1000
	orr	r6, r5, #0x8000

	mov	r2, #0x40
	orr	r2, r2, #0x4000
	mov	r3, #0x80
	//orr	r3, r3, #0x8000
	mov	r4, #0xff
	orr	r4, r4, #0xff00
1:
	strh	r2, [r1]
	ldrh	r7, [r5]
	strh	r7, [r1]

2:
	ldrh	r7, [r1]
	tst	r7, r3
	beq	2b

	strh	r4, [r1]
	add	r1, r1, #2
	add	r5, r5, #2
	cmp	r5, r6
	bne	1b

	nop
	nop
3:
	b	3b

