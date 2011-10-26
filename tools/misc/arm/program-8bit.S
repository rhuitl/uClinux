#define MACH_SG565

.text
.global _start

_start:
#ifdef MACH_SG565
	ldr	r1, gpoer
	ldr	r2, gpoerval
	str	r2, [r1]	
	ldr	r1, gpoutr
	ldr	r2, gpoutrval
	str	r2, [r1]	
#endif

	mov	r1, #0x50000000
	mov	r2, #0x40
	mov	r3, #0x80
	mov	r4, #0xff
	mov	r5, #0
	mov	r6, #0x40000
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

#ifdef MACH_SG565
	ldr	r1, gpoutr
	mov	r2, #0
	str	r2, [r1]
#endif
	nop
	nop
3:
	b	3b

#ifdef MACH_SG565
gpoer:
	.long	0xc8004004
gpoerval:
	.long	0x00003b03
gpoutr:
	.long	0xc8004000
gpoutrval:
	.long	0x000004fc
#endif
