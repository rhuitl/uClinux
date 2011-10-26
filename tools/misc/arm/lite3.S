
.text
.global _start
//
// Enter with:
//
//  r1  ==  FLASH address to program into
//  r5  ==  RAM address to get data from
//  r6  ==  RAM end address
//

_start:
	mov	r2, #0x40
	mov	r3, #0x80
	mov	r4, #0xff
1:
	strb	r2, [r1]
	ldrb	r7, [r5]
	strb	r7, [r1]

2:
	ldrb	r7, [r1]
	tst	r7, r3
	beq	2b

	strb	r4, [r1]
	add	r1, r1, #1
	add	r5, r5, #1
	cmp	r5, r6
	bne	1b

	nop
	nop
3:
	b	3b

