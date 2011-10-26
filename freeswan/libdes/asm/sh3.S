	.little
	.text
	.align 2
/* Through this assembly, registers r13 and r14 hold the left and right
 * half values (l & r).  Which value is assigned to which register varies
 * as they are periodically swapped over.
 *
 * Input:
 * r4	252
 * r5	encryption key
 * r13	l/r
 * r14	r/l
 *
 * Output:
 * r1	same as r13	(assist with swapping r13 & r14)
 * r4	252
 * r13	l/r
 * r14	r/l
 *
 * Internally:
 * r0	temporary
 * r1	temporary
 * r2	temporary
 * r3	temporary then 1792
 * r5	temporary
 * r6	misc constants
 * r7	loop index
 * r8	key pointer	(r9 in decrypt)
 * r9	temporary	(r8 in decrypt)
 * r10	temporary
 * r11	temporary
 *
 * Unused:
 * r12	unused and not saved by caller
 */

des_encrypt2:
	/* No need to save registers here since our caller has already done
	 * this for us.
	 */
	mov.l	@r5,r1
	mov	r5,r8
	mov	#0,r7
	mov	r14,r11
enc2_loop:
	xor	r1,r11
	mov	r14,r10
	mov.l	@(4,r8),r1
	mov	r11,r3
	xor	r1,r10
	mov	r11,r1
	shlr8	r3
	and	r4,r1
	mov.l	enc2_0,r0
	and	r4,r3
	mov.l	@(r0,r1),r2
	shlr16	r11
	mov.l	enc2_512,r0
	rotr	r10
	mov.l	@(r0,r3),r1
	xor	r1,r2
	mov.l	enc2_1024,r0
	mov	r11,r1
	shlr8	r11
	and	r4,r1
	mov.l	@(r0,r1),r1
	and	r4,r11
	mov.l	enc2_1536,r6
	rotr	r10
	mov	r11,r0
	xor	r1,r2
	mov.l	@(r0,r6),r1
	rotr	r10
	xor	r1,r2
	rotr	r10
	mov.l	enc2_256,r6
	mov	r10,r0
	and	r4,r0
	mov.l	@(r0,r6),r1	/* misaligned */
	mov	r10,r0
	shlr8	r0
	mov.l	enc2_768,r6
	and	r4,r0
	xor	r1,r2
	shlr16	r10
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_1280,r6
	xor	r1,r2
	and	r4,r0
	shlr8	r10
	mov.l	@(r0,r6),r1
	and	r4,r10
	mov.l	enc2_1792,r3
	xor	r1,r2
	mov	r10,r0
	mov.l	@(r0,r3),r1	/* misaligned */
	xor	r1,r2
	xor	r2,r13
	mov.l	@(8,r8),r1
	mov	r13,r11
	xor	r1,r11
	mov	r11,r9
	mov.l	@(12,r8),r1
	shlr8	r9
	mov	r13,r10
	mov	r9,r0
	xor	r1,r10
	and	r4,r0
	mov	r11,r1
	mov	r0,r5
	and	r4,r1
	shlr16	r11
	mov.l	enc2_0,r0
	rotr	r10
	mov.l	@(r0,r1),r2
	mov	r5,r0
	mov.l	enc2_512,r9
	rotr	r10
	mov.l	@(r0,r9),r1
	rotr	r10
	xor	r1,r2
	mov	r11,r1
	mov.l	enc2_1024,r0
	and	r4,r1
	mov.l	@(r0,r1),r1
	shlr8	r11
	xor	r1,r2
	and	r4,r11
	mov.l	enc2_1536,r6
	mov	r11,r0
	mov.l	@(r0,r6),r1
	rotr	r10
	xor	r1,r2
	mov	r10,r0
	mov.l	enc2_256,r6
	and	#252,r0
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_768,r6
	shlr8	r0
	xor	r1,r2
	and	#252,r0
	mov.l	@(r0,r6),r1
	shlr16	r10
	xor	r1,r2
	mov	r10,r0
	mov.l	enc2_1280,r6
	and	#252,r0
	shlr8	r10
	and	r4,r10
	mov.l	@(r0,r6),r1
	mov	r10,r0
	xor	r1,r2
	mov.l	@(r0,r3),r1	/* misaligned */
	xor	r1,r2
	xor	r2,r14
	mov.l	@(16,r8),r1
	mov	r14,r11
	xor	r1,r11
	mov	r11,r9
	mov.l	@(20,r8),r1
	shlr8	r9
	mov	r14,r10
	mov	r9,r0
	xor	r1,r10
	and	r4,r0
	mov	r11,r1
	mov	r0,r5
	mov.l	enc2_0,r0
	and	r4,r1
	mov.l	@(r0,r1),r2
	mov	r5,r0
	mov.l	enc2_512,r9
	rotr	r10
	mov.l	@(r0,r9),r1
	shlr16	r11
	rotr	r10
	xor	r1,r2
	mov	r11,r1
	rotr	r10
	mov.l	enc2_1024,r0
	and	r4,r1
	mov.l	@(r0,r1),r1
	shlr8	r11
	xor	r1,r2
	and	r4,r11
	mov.l	enc2_1536,r6
	rotr	r10
	mov	r11,r0
	mov.l	@(r0,r6),r1	/* misaligned */
	mov	r10,r0
	xor	r1,r2
	mov.l	enc2_256,r6
	and	#252,r0
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_768,r6
	shlr8	r0
	xor	r1,r2
	and	#252,r0
	mov.l	@(r0,r6),r1
	shlr16	r10
	mov.l	enc2_1280,r6
	mov	r10,r0
	xor	r1,r2
	and	#252,r0
	mov.l	@(r0,r6),r1
	shlr8	r10
	xor	r1,r2
	and	r4,r10
	mov	r10,r0
	mov.l	@(r0,r3),r1	/* misaligned */
	xor	r1,r2
	xor	r2,r13
	mov.l	@(24,r8),r1
	mov	r13,r11
	xor	r1,r11
	mov	r11,r9
	mov.l	@(28,r8),r1
	shlr8	r9
	mov	r13,r10
	mov	r9,r0
	xor	r1,r10
	and	r4,r0
	mov	r11,r1
	mov	r0,r5
	mov.l	enc2_0,r0
	and	r4,r1
	mov.l	@(r0,r1),r2
	shlr16	r11
	mov	r5,r0
	rotr	r10
	mov.l	enc2_512,r9
	rotr	r10
	mov.l	@(r0,r9),r1
	rotr	r10
	xor	r1,r2
	mov	r11,r1
	mov.l	enc2_1024,r0
	and	r4,r1
	shlr8	r11
	rotr	r10
	mov.l	@(r0,r1),r1
	and	r4,r11
	mov.l	enc2_1536,r6
	xor	r1,r2
	mov	r11,r0
	add	#8,r7
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_256,r6
	and	#252,r0
	xor	r1,r2
	mov.l	@(r0,r6),r1	/* misaligned */
	mov	r10,r0
	shlr8	r0
	mov.l	enc2_768,r6
	and	#252,r0
	xor	r1,r2
	shlr16	r10
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_1280,r6
	and	#252,r0
	xor	r1,r2
	shlr8	r10
	mov.l	@(r0,r6),r1
	and	r4,r10
	xor	r1,r2
	mov	r10,r0
	mov.l	@(r0,r3),r1
	mov	#31,r6
	cmp/gt	r6,r7
	xor	r1,r2
	add	#32,r8
	xor	r2,r14
	bt	enc2_exit
	mov.l	@r8,r1		/* misaligned */
	bra	enc2_loop
	mov	r14,r11
enc2_exit:
	rts	
	mov	r13,r1

/* This routine is the converse of the above.
 * It expects the same arguments in the same registers as des_encrypt2
 * and it produces the same output.  The only real difference is the
 * order of the encryption.
 */
des_decrypt2:
	/* No need to save registers here since our caller has already done
	 * this for us.
	 */
	add	#96,r5
	mov	#30,r7
	mov.l	@(24,r5),r1
	mov	r14,r11
	mov	r5,r9
dec2_loop:
	xor	r1,r11
	mov.l	@(28,r9),r1
	mov	r14,r10
	xor	r1,r10
	mov	r11,r1
	mov.l	enc2_0,r0
	and	r4,r1
	mov	r11,r3
	shlr8	r3
	mov.l	@(r0,r1),r2
	and	r4,r3
	mov.l	enc2_512,r0
	shlr16	r11
	mov.l	@(r0,r3),r1
	xor	r1,r2
	mov	r11,r1
	and	r4,r1
	mov.l	enc2_1024,r0
	shlr8	r11
	mov.l	@(r0,r1),r1
	and	r4,r11
	mov.l	enc2_1536,r6
	rotr	r10
	mov	r11,r0
	rotr	r10
	xor	r1,r2
	rotr	r10
	mov.l	@(r0,r6),r1
	rotr	r10
	mov.l	enc2_256,r6
	mov	r10,r0
	and	r4,r0
	xor	r1,r2
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_768,r6
	shlr8	r0
	xor	r1,r2
	and	r4,r0
	mov.l	@(r0,r6),r1
	shlr16	r10
	mov.l	enc2_1280,r6
	mov	r10,r0
	xor	r1,r2
	and	r4,r0
	mov.l	@(r0,r6),r1
	shlr8	r10
	mov.l	enc2_1792,r3
	and	r4,r10
	xor	r1,r2
	mov	r10,r0
	mov.l	@(r0,r3),r1
	xor	r1,r2
	mov.l	@(16,r9),r1
	xor	r2,r13
	mov	r13,r11
	xor	r1,r11
	mov.l	@(20,r9),r1
	mov	r11,r2
	mov	r13,r10
	shlr8	r2
	xor	r1,r10
	mov	r2,r0
	mov	r11,r1
	and	r4,r0
	and	r4,r1
	mov	r0,r5
	mov.l	enc2_0,r0
	rotr	r10
	mov.l	@(r0,r1),r2
	mov	r5,r0
	mov.l	enc2_512,r8
	rotr	r10
	mov.l	@(r0,r8),r1
	shlr16	r11
	xor	r1,r2
	mov	r11,r1
	mov.l	enc2_1024,r0
	shlr8	r11
	and	r4,r1
	rotr	r10
	mov.l	@(r0,r1),r1
	rotr	r10
	xor	r1,r2
	and	r4,r11
	mov.l	enc2_1536,r6
	mov	r11,r0
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_256,r6
	xor	r1,r2
	and	#252,r0
	mov.l	@(r0,r6),r1	/* misaligned */
	mov	r10,r0
	shlr8	r0
	mov.l	enc2_768,r6
	and	#252,r0
	xor	r1,r2
	shlr16	r10
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_1280,r6
	and	#252,r0
	xor	r1,r2
	shlr8	r10
	mov.l	@(r0,r6),r1
	and	r4,r10
	xor	r1,r2
	mov	r10,r0
	mov.l	@(r0,r3),r1
	xor	r1,r2
	mov.l	@(8,r9),r1
	xor	r2,r14
	mov	r14,r11
	xor	r1,r11
	mov.l	@(12,r9),r1
	mov	r11,r8
	mov	r14,r10
	shlr8	r8
	xor	r1,r10
	mov	r8,r0
	mov	r11,r1
	and	r4,r0
	mov	r0,r5
	and	r4,r1
	mov.l	enc2_0,r0
	shlr16	r11
	mov.l	@(r0,r1),r2
	mov	r5,r0
	mov.l	enc2_512,r8
	rotr	r10
	mov.l	@(r0,r8),r1
	rotr	r10
	xor	r1,r2
	mov	r11,r1
	rotr	r10
	and	r4,r1
	mov.l	enc2_1024,r0
	shlr8	r11
	mov.l	@(r0,r1),r1
	and	r4,r11
	mov.l	enc2_1536,r6
	xor	r1,r2
	rotr	r10
	mov	r11,r0
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_256,r6
	and	#252,r0
	xor	r1,r2
	mov.l	@(r0,r6),r1	/* misaligned */
	mov	r10,r0
	xor	r1,r2
	mov.l	enc2_768,r6
	shlr8	r0
	shlr16	r10
	and	#252,r0
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_1280,r6
	and	#252,r0
	xor	r1,r2
	shlr8	r10
	mov.l	@(r0,r6),r1
	and	r4,r10
	xor	r1,r2
	mov	r10,r0
	mov.l	@(r0,r3),r1
	xor	r1,r2
	mov.l	@r9,r1
	xor	r2,r13
	mov	r13,r11
	xor	r1,r11
	mov	r11,r8
	shlr8	r8
	mov.l	@(4,r9),r1
	mov	r8,r0
	mov	r13,r10
	and	r4,r0
	xor	r1,r10
	mov	r11,r1
	mov	r0,r5
	and	r4,r1
	mov.l	enc2_0,r0
	shlr16	r11
	mov.l	@(r0,r1),r2
	rotr	r10
	mov.l	enc2_512,r8
	mov	r5,r0
	mov.l	@(r0,r8),r1
	rotr	r10
	xor	r1,r2
	rotr	r10
	mov.l	enc2_1024,r0
	mov	r11,r1
	and	r4,r1
	shlr8	r11
	mov.l	@(r0,r1),r1
	and	r4,r11
	mov.l	enc2_1536,r6
	xor	r1,r2
	mov	r11,r0
	rotr	r10
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_256,r6
	xor	r1,r2
	and	#252,r0
	add	#-32,r9
	mov.l	@(r0,r6),r1
	mov	r10,r0
	mov.l	enc2_768,r6
	shlr8	r0
	and	#252,r0
	xor	r1,r2
	mov.l	@(r0,r6),r1
	shlr16	r10
	mov.l	enc2_1280,r6
	mov	r10,r0
	and	#252,r0
	xor	r1,r2
	shlr8	r10
	and	r4,r10
	mov.l	@(r0,r6),r1
	mov	r10,r0
	xor	r1,r2
	add	#-8,r7
	mov.l	@(r0,r3),r1
	cmp/pl	r7
	xor	r1,r2
	xor	r2,r14
	bf	dec2_exit
	mov.l	@(24,r9),r1	/* misaligned */
	bra	dec2_loop
	mov	r14,r11
dec2_exit:
	rts
	mov	r13,r1	
	
	.align 2
enc2_0:		.long	des_SPtrans
enc2_512:	.long	des_SPtrans + 512
enc2_1024:	.long	des_SPtrans + 1024
enc2_1536:	.long	des_SPtrans + 1536
enc2_256:	.long	des_SPtrans + 256
enc2_768:	.long	des_SPtrans + 768
enc2_1280:	.long	des_SPtrans + 1280
enc2_1792:	.long	des_SPtrans + 1792
	
	
	.align	2
	.global	des_encrypt3
	.type	des_encrypt3,@function
des_encrypt3:
	mov.l	r8,@-r15	/* Save all registers here to */
	mov.l	r9,@-r15	/* avoid having the work routine */
	mov.l	r10,@-r15	/* do it for each des invocation */
	mov.l	r11,@-r15
	mov.l	r13,@-r15
	mov.l	r14,@-r15
	sts.l	pr,@-r15	/* Return address */
	mov.l	r4,@-r15	/* Save data pointer till end */
	mov.l	r7,@-r15	/* Save Key 3 */
	mov.l	@(4,r4),r13	/* data[1] */
	mov.l	r6,@-r15	/* Save Key 2 */
	mov	r13,r1
	mov.l	@r4,r14		/* data[2] */
	shlr2	r1		/* Perform the IP permutation */
	mov.l	cnst0x0f0f0f0f,r6
	mov	#4,r7
	shlr2	r1
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	shld	r7,r1
	xor	r1,r13
	mov	r14,r1
	shlr16	r1
	mov.l	cnst0x0000ffff,r6
	xor	r13,r1
	mov.w	cnst252,r4
	and	r6,r1
	xor	r1,r13
	shll16	r1
	xor	r1,r14
	mov	r13,r1
	mov.l	cnst0x33333333,r6
	shlr2	r1
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	shll2	r1
	xor	r1,r13
	mov	r14,r1
	shlr8	r1
	xor	r13,r1
	mov.l	cnst0x00ff00ff,r6
	and	r6,r1
	xor	r1,r13
	shll8	r1
	xor	r1,r14
	mov	r13,r1
	shlr	r1
	xor	r14,r1
	mov.l	cnst0x55555555,r6
	and	r6,r1
	xor	r1,r14
	add	r1,r1
	xor	r1,r13
	rotl	r14
	rotl	r13
	rotl	r14
	rotl	r13
	rotl	r14
	bsr	des_encrypt2
	rotl	r13
	mov.l	@r15+,r5	/* recover key 2 */
	mov	r14,r13
	bsr	des_decrypt2
	mov	r1,r14
	mov.l	@r15+,r5	/* recover key 3 */
	mov	r14,r13
	bsr	des_encrypt2
	mov	r1,r14
	rotr	r14
	rotr	r13
	rotr	r14
	rotr	r13
	rotr	r14
	rotr	r13
	mov	r14,r1		/* Perform the FP permutation */
	shlr	r1
	mov.l	cnst0x55555555,r6
	xor	r13,r1
	and	r6,r1
	xor	r1,r13
	add	r1,r1
	xor	r1,r14
	mov	r13,r1
	shlr8	r1
	mov.l	cnst0x00ff00ff,r6
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	shll8	r1
	xor	r1,r13
	mov	r14,r1
	shlr2	r1
	mov.l	cnst0x33333333,r6
	xor	r13,r1
	and	r6,r1
	xor	r1,r13
	shll2	r1
	xor	r1,r14
	mov	r13,r1
	shlr16	r1
	mov.l	cnst0x0000ffff,r6
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	mov.l	@r15+,r9
	shll16	r1
	xor	r1,r13
	mov	r14,r1
	mov.l	cnst0x0f0f0f0f,r6
	shlr2	r1
	shlr2	r1
	xor	r13,r1
	mov	#4,r7
	and	r6,r1
	xor	r1,r13
	shld	r7,r1
	xor	r1,r14
	mov.l	r14,@(4,r9)	/* data[1] */
	lds.l	@r15+,pr
	mov.l	@r15+,r14
	mov.l	r13,@r9		/* data[0] */
	mov.l	@r15+,r13
	mov.l	@r15+,r11
	mov.l	@r15+,r10
	mov.l	@r15+,r9
	rts	
	mov.l	@r15+,r8

	.align	2
	.global	des_decrypt3
	.type	des_decrypt3,@function
des_decrypt3:
	mov.l	r8,@-r15	/* Save all registers here to */
	mov.l	r9,@-r15	/* avoid having the work routine */
	mov.l	r10,@-r15	/* do it for each des invocation */
	mov.l	r11,@-r15
	mov.l	r13,@-r15
	mov.l	r14,@-r15
	sts.l	pr,@-r15	/* Return address */
	mov.l	r4,@-r15	/* Save data pointer for end */
	mov.l	r5,@-r15	/* Save Key 1 */
	mov.l	r6,@-r15	/* Save Key 2 */
	mov.l	@(4,r4),r13	/* data[1] */
	mov	r13,r1
	mov.l	@r4,r14		/* data[0] */
	mov	r7,r5
	shlr2	r1		/* Perform IP permutation */
	shlr2	r1
	mov.l	cnst0x0f0f0f0f,r6
	xor	r14,r1
	and	r6,r1
	mov	#4,r6
	xor	r1,r14
	shld	r6,r1
	mov.w	cnst252,r4
	xor	r1,r13
	mov	r14,r1
	shlr16	r1
	mov.l	cnst0x0000ffff,r6
	xor	r13,r1
	and	r6,r1
	xor	r1,r13
	shll16	r1
	xor	r1,r14
	mov	r13,r1
	shlr2	r1
	mov.l	cnst0x33333333,r6
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	shll2	r1
	xor	r1,r13
	mov	r14,r1
	shlr8	r1
	mov.l	cnst0x00ff00ff,r6
	xor	r13,r1
	and	r6,r1
	xor	r1,r13
	shll8	r1
	xor	r1,r14
	mov	r13,r1
	shlr	r1
	mov.l	cnst0x55555555,r6
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	add	r1,r1
	xor	r1,r13
	rotl	r14
	rotl	r13
	rotl	r14
	rotl	r13
	rotl	r14
	bsr	des_decrypt2
	rotl	r13
	mov	r14,r13
	mov.l	@r15+,r5	/* Recover key2 */
	bsr	des_encrypt2
	mov	r1,r14
	mov	r14,r13
	mov.l	@r15+,r5	/* Recover key1 */
	bsr	des_decrypt2
	mov	r1,r14
	rotr	r14
	rotr	r13
	rotr	r14
	rotr	r13
	rotr	r14
	rotr	r13
	mov	r14,r1		/* Perform FP permutation */
	mov.l	cnst0x55555555,r6
	shlr	r1
	xor	r13,r1
	and	r6,r1
	xor	r1,r13
	add	r1,r1
	xor	r1,r14
	mov	r13,r1
	mov.l	cnst0x00ff00ff,r6
	shlr8	r1
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	shll8	r1
	xor	r1,r13
	mov	r14,r1
	mov.l	cnst0x33333333,r6
	shlr2	r1
	xor	r13,r1
	and	r6,r1
	xor	r1,r13
	shll2	r1
	xor	r1,r14
	mov	r13,r1
	mov.l	cnst0x0000ffff,r6
	shlr16	r1
	xor	r14,r1
	and	r6,r1
	xor	r1,r14
	mov.l	@r15+,r9
	shll16	r1
	xor	r1,r13
	mov	r14,r1
	shlr2	r1
	mov.l	cnst0x0f0f0f0f,r6
	shlr2	r1
	xor	r13,r1
	mov	#4,r7
	and	r6,r1
	xor	r1,r13
	shld	r7,r1
	xor	r1,r14
	mov.l	r14,@(4,r9)	/* data[1] */
	lds.l	@r15+,pr
	mov.l	@r15+,r14
	mov.l	r13,@r9		/* data[0] */
	mov.l	@r15+,r13
	mov.l	@r15+,r11
	mov.l	@r15+,r10
	mov.l	@r15+,r9
	rts	
	mov.l	@r15+,r8

cnst252:	.short	252

		.align 2
cnst0x0f0f0f0f:	.long	252645135
cnst0x0000ffff:	.long	65535
cnst0x33333333:	.long	858993459
cnst0x00ff00ff:	.long	16711935
cnst0x55555555:	.long	1431655765

