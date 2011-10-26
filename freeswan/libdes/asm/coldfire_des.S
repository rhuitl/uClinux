	.file	"des_encrypt2.s"
	.version	"01.01"
.text

/****************************************************************************/

.align 	16
.globl des_encrypt3

des_encrypt3:
	lea %sp@(-52),%sp
	moveml %d2-%d7/%a2-%fp, (%sp)

	move.l 56(%sp),%a3
	move.l (%a3),%d5		/* l = data[0] */
	move.l 4(%a3),%d4		/* r = data[1] */

	move.l %d4,%d0			/* tt = ((r>>4)^l)&0x0f0f0f0fL, */
	lsr.l #4,%d0
	eor.l %d5,%d0
	and.l #252645135,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	lsl.l #4,%d0			/* r ^= (tt<<4); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt = ((l>>16)^r)&0x0000ffffL, */
	clr.w %d0
	swap %d0
	eor.l %d4,%d0
	and.l #65535,%d0

	eor.l %d0,%d4			/* r ^= tt, */

	swap %d0
	clr.w %d0
	eor.l %d0,%d5			/* l ^= (tt<<16); */


	move.l %d4,%d0			/* tt = ((r>>2)^l)&0x33333333L, */
	lsr.l #2,%d0
	eor.l %d5,%d0
	and.l #858993459,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	lsl.l #2,%d0			/* r ^= (tt<<2); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt = ((l>>8)^r)&0x00ff00ff, */
	lsr.l #8,%d0
	eor.l %d4,%d0
	and.l #16711935,%d0

	eor.l %d0,%d4			/* r ^= tt, */

	lsl.l #8,%d0			/* l ^= (tt<<8); */
	eor.l %d0,%d5


	move.l %d4,%d0			/* tt = ((r>>1)^l)&0x55555555, */
	lsr.l #1,%d0
	eor.l %d5,%d0
	and.l #1431655765,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	add.l %d0,%d0			/* r ^= (tt<<1); */
	eor.l %d0,%d4

	/* ----------------------------------- */
	/* ASSUME: r=data[0]=%d5, l=data[1]=%d4 */

	moveq.l #29,%d7
	move.l %d5,%d0			/* r=ROTATE(r,29)&0xffffffffL; */
	lsr.l %d7,%d0
	lsl.l #3,%d5
	add.l %d0,%d5

	move.l %d4,%d0			/* l=ROTATE(l,29)&0xffffffffL; */
	lsr.l %d7,%d0
	lsl.l #3,%d4
	add.l %d0,%d4

	lea des_SPtrans,%a3		/* Constants extracted from loop */
	lea des_SPtrans+256,%a4
	lea des_SPtrans+768,%a6
	lea des_SPtrans+1280,%a5
	move.l #252,%d1			/* mask constant */


	move.l 60(%sp),%a0		/* load key pointer */
	move.l #8,%a1			/* key incrementer */
	jbsr des_fastencrypt2

	move.l 64(%sp),%a0		/* load key pointer */
	lea (120,%a0),%a0		/* start at end of key */
	move.l #-8,%a1			/* key incrementer */
	jbsr des_fastencrypt2

	move.l 68(%sp),%a0		/* load key pointer */
	move.l #8,%a1			/* key incrementer */
	jbsr des_fastencrypt2


	/* ASSUME: d5=data[0], d4=data[1] */
	moveq.l #29,%d7
	move.l %d5,%d0			/* data[0]=ROTATE(l,3)&0xffffffffL; */
	lsl.l %d7,%d0
	lsr.l #3,%d5
	or.l %d0,%d5

	move.l %d4,%d1			/* data[1]=ROTATE(r,3)&0xffffffffL; */
	lsl.l %d7,%d1
	lsr.l #3,%d4
	or.l %d1,%d4

	/* ----------------------------------- */

	move.l %d4,%d0			/* tt =(((r>>1)^l)&0x55555555L), */
	lsr.l #1,%d0
	eor.l %d5,%d0
	and.l #1431655765,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	add.l %d0,%d0			/* r ^= (tt<<1); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt =(((l>>8)^r)&0x00ff00ffL), */
	lsr.l #8,%d0
	eor.l %d4,%d0
	and.l #16711935,%d0

	eor.l %d0,%d4			/* r ^= tt, */

	lsl.l #8,%d0			/* l ^= (tt<<8); */
	eor.l %d0,%d5


	move.l %d4,%d0			/* tt =(((r>>2)^l)&0x33333333L), */
	lsr.l #2,%d0
	eor.l %d5,%d0
	and.l #858993459,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	lsl.l #2,%d0			/* r ^= (tt<<2); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt =(((l>>16)^r)&0x0000ffffL), */
	clr.w %d0
	swap %d0
	eor.l %d4,%d0
	and.l #65535,%d0

	eor.l %d0,%d4			/* r ^=tt, */

	swap %d0			/* l ^= (tt<<16); */
	clr.w %d0
	eor.l %d0,%d5

	move.l %d4,%d0			/* tt =(((r>>4)^l)&0x0f0f0f0fL), */
	lsr.l #4,%d0
	eor.l %d5,%d0
	and.l #252645135,%d0

	move.l 56(%sp),%a3
	eor.l %d0,%d5			/* l ^= tt, */
	move.l %d5,(%a3)

	lsl.l #4,%d0			/* r ^= (tt<<4); */
	eor.l %d0,%d4
	move.l %d4,4(%a3)

        moveml (%sp), %d2-%d7/%a2-%fp
        add.l #52, %sp
	rts

/****************************************************************************/

.align 	16
.globl des_decrypt3

des_decrypt3:
	lea %sp@(-52),%sp
	moveml %d2-%d7/%a2-%fp, (%sp)

	move.l 56(%sp),%a3
	move.l (%a3),%d5		/* l = data[0] */
	move.l 4(%a3),%d4		/* r = data[1] */

	move.l %d4,%d0			/* tt = ((r>>4)^l)&0x0f0f0f0fL, */
	lsr.l #4,%d0
	eor.l %d5,%d0
	and.l #252645135,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	lsl.l #4,%d0			/* r ^= (tt<<4); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt = ((l>>16)^r)&0x0000ffffL, */
	clr.w %d0
	swap %d0
	eor.l %d4,%d0
	and.l #65535,%d0

	eor.l %d0,%d4			/* r ^= tt, */

	swap %d0
	clr.w %d0
	eor.l %d0,%d5			/* l ^= (tt<<16); */


	move.l %d4,%d0			/* tt = ((r>>2)^l)&0x33333333L, */
	lsr.l #2,%d0
	eor.l %d5,%d0
	and.l #858993459,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	lsl.l #2,%d0			/* r ^= (tt<<2); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt = ((l>>8)^r)&0x00ff00ff, */
	lsr.l #8,%d0
	eor.l %d4,%d0
	and.l #16711935,%d0

	eor.l %d0,%d4			/* r ^= tt, */

	lsl.l #8,%d0			/* l ^= (tt<<8); */
	eor.l %d0,%d5


	move.l %d4,%d0			/* tt = ((r>>1)^l)&0x55555555, */
	lsr.l #1,%d0
	eor.l %d5,%d0
	and.l #1431655765,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	add.l %d0,%d0			/* r ^= (tt<<1); */
	eor.l %d0,%d4

	/* ----------------------------------- */
	/* ASSUME: r=data[0]=%d5, l=data[1]=%d4 */

	moveq.l #29,%d7
	move.l %d5,%d0			/* r=ROTATE(r,29)&0xffffffffL; */
	lsr.l %d7,%d0
	lsl.l #3,%d5
	add.l %d0,%d5

	move.l %d4,%d0			/* l=ROTATE(l,29)&0xffffffffL; */
	lsr.l %d7,%d0
	lsl.l #3,%d4
	add.l %d0,%d4

	lea des_SPtrans,%a3		/* Constants extracted from loop */
	lea des_SPtrans+256,%a4
	lea des_SPtrans+768,%a6
	lea des_SPtrans+1280,%a5
	move.l #252,%d1			/* mask constant */


	move.l 68(%sp),%a0		/* load key pointer */
	lea (120,%a0),%a0		/* start at end of key */
	move.l #-8,%a1			/* key incrementer */
	jbsr des_fastencrypt2

	move.l 64(%sp),%a0		/* load key pointer */
	move.l #8,%a1			/* key incrementer */
	jbsr des_fastencrypt2

	move.l 60(%sp),%a0		/* load key pointer */
	lea (120,%a0),%a0		/* start at end of key */
	move.l #-8,%a1			/* key incrementer */
	jbsr des_fastencrypt2


	/* ASSUME: d5=data[0], d4=data[1] */
	moveq.l #29,%d7
	move.l %d5,%d0			/* data[0]=ROTATE(l,3)&0xffffffffL; */
	lsl.l %d7,%d0
	lsr.l #3,%d5
	or.l %d0,%d5

	move.l %d4,%d1			/* data[1]=ROTATE(r,3)&0xffffffffL; */
	lsl.l %d7,%d1
	lsr.l #3,%d4
	or.l %d1,%d4

	/* ----------------------------------- */

	move.l %d4,%d0			/* tt =(((r>>1)^l)&0x55555555L), */
	lsr.l #1,%d0
	eor.l %d5,%d0
	and.l #1431655765,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	add.l %d0,%d0			/* r ^= (tt<<1); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt =(((l>>8)^r)&0x00ff00ffL), */
	lsr.l #8,%d0
	eor.l %d4,%d0
	and.l #16711935,%d0

	eor.l %d0,%d4			/* r ^= tt, */

	lsl.l #8,%d0			/* l ^= (tt<<8); */
	eor.l %d0,%d5


	move.l %d4,%d0			/* tt =(((r>>2)^l)&0x33333333L), */
	lsr.l #2,%d0
	eor.l %d5,%d0
	and.l #858993459,%d0

	eor.l %d0,%d5			/* l ^= tt, */

	lsl.l #2,%d0			/* r ^= (tt<<2); */
	eor.l %d0,%d4


	move.l %d5,%d0			/* tt =(((l>>16)^r)&0x0000ffffL), */
	clr.w %d0
	swap %d0
	eor.l %d4,%d0
	and.l #65535,%d0

	eor.l %d0,%d4			/* r ^=tt, */

	swap %d0			/* l ^= (tt<<16); */
	clr.w %d0
	eor.l %d0,%d5

	move.l %d4,%d0			/* tt =(((r>>4)^l)&0x0f0f0f0fL), */
	lsr.l #4,%d0
	eor.l %d5,%d0
	and.l #252645135,%d0

	move.l 56(%sp),%a3
	eor.l %d0,%d5			/* l ^= tt, */
	move.l %d5,(%a3)

	lsl.l #4,%d0			/* r ^= (tt<<4); */
	eor.l %d0,%d4
	move.l %d4,4(%a3)

        moveml (%sp), %d2-%d7/%a2-%fp
        add.l #52, %sp
	rts

/****************************************************************************/

.align	16
.globl des_fastencrypt2

des_fastencrypt2:
	/* ASSUME: a0=key, a1=incrementer, d5=r=data[0], d4=l=data[1] */

	move.l #7, %d6			/* for (i = 0; (i<32); i += 4) */

.L19:
	move.l (%a0),%d2		/* u = r ^ s[i+0]; */
	eor.l %d5,%d2

	move.l 4(%a0),%d3		/* t = r ^ s[i+0+1]; */
	eor.l %d5,%d3

	move.l %d3,%d0			/* t = ((t >> 4) + (t << (32-4)); */
	lsr.l #4,%d0
	moveq.l #28,%d7
	lsl.l %d7,%d3
	add.l %d0,%d3


	move.l %d2,%d0			/* des_SPtrans[0][(u>>2L)&0x3f] */
	and.l %d1,%d0
	move.l (%a3,%d0.l),%d0
	eor.l %d0,%d4

	move.l %d2,%d0			/* des_SPtrans[2][(u>>10L)&0x3f] */
	lsr.l #8,%d0
	and.l %d1,%d0
	lea des_SPtrans+512,%a2
	move.l (%a2,%d0.l),%d0
	eor.l %d0,%d4

	clr.w %d2			/* des_SPtrans[4][(u>>18L)&0x3f] */
	swap %d2
	move.l %d2,%d0
	and.l %d1,%d0
	lea des_SPtrans+1024,%a2
	move.l (%a2,%d0.l),%d0
	eor.l %d0,%d4

	moveq.l #10,%d7			/* des_SPtrans[6][(u>>26L)&0x3f] */
	lsr.l %d7,%d2
	lea des_SPtrans+1536,%a2
	move.l (%a2,%d2.l*4),%d2
	eor.l %d2,%d4

	move.l %d3,%d0			/* des_SPtrans[1][(t>>2L)&0x3f] */
	and.l %d1,%d0
	move.l (%a4,%d0.l),%d0
	eor.l %d0,%d4

	move.l %d3,%d0			/* des_SPtrans[3][(t>>10L)&0x3f] */
	lsr.l #8,%d0
	and.l %d1,%d0
	move.l (%a6,%d0.l),%d0
	eor.l %d0,%d4

	clr.w %d3			/* des_SPtrans[5][(t>>18L)&0x3f] */
	swap %d3
	move.l %d3,%d0
	and.l %d1,%d0
	move.l (%a5,%d0.l),%d0
	eor.l %d0,%d4

	lsr.l %d7,%d3			/* des_SPtrans[7][(t>>26L)&0x3f] */
	lea des_SPtrans+1792,%a2
	move.l (%a2,%d3.l*4),%d3
	eor.l %d3,%d4

	/* ---- */

	add.l %a1,%a0			/* s += 2 */

	move.l (%a0),%d2		/* u = l ^ s[i+0]; */
	eor.l %d4,%d2

	move.l 4(%a0),%d3		/* t = l ^ s[i+0+1]; */
	eor.l %d4,%d3

	move.l %d3,%d0			/* t = ((t >> 4) + (t << (32-4)); */
	lsr.l #4,%d0
	moveq.l #28,%d7
	lsl.l %d7,%d3
	add.l %d0,%d3


	move.l %d2,%d0			/* des_SPtrans[0][(u>>2L)&0x3f] */
	and.l %d1,%d0
	move.l (%a3,%d0.l),%d0
	eor.l %d0,%d5

	move.l %d2,%d0			/* des_SPtrans[2][(u>>10L)&0x3f] */
	lsr.l #8,%d0
	and.l %d1,%d0
	lea des_SPtrans+512,%a2
	move.l (%a2,%d0.l),%d0
	eor.l %d0,%d5

	clr.w %d2			/* des_SPtrans[4][(u>>18L)&0x3f] */
	swap %d2
	move.l %d2,%d0
	and.l %d1,%d0
	lea des_SPtrans+1024,%a2
	move.l (%a2,%d0.l),%d0
	eor.l %d0,%d5

	moveq.l #10,%d7			/* des_SPtrans[6][(u>>26L)&0x3f] */
	lsr.l %d7,%d2
	lea des_SPtrans+1536,%a2
	move.l (%a2,%d2.l*4),%d2
	eor.l %d2,%d5

	move.l %d3,%d0			/* des_SPtrans[1][(t>>2L)&0x3f] */
	and.l %d1,%d0
	move.l (%a4,%d0.l),%d0
	eor.l %d0,%d5

	move.l %d3,%d0			/* des_SPtrans[3][(t>>10L)&0x3f] */
	lsr.l #8,%d0
	and.l %d1,%d0
	move.l (%a6,%d0.l),%d0
	eor.l %d0,%d5

	clr.w %d3			/* des_SPtrans[5][(t>>18L)&0x3f] */
	swap %d3
	move.l %d3,%d0
	and.l %d1,%d0
	move.l (%a5,%d0.l),%d0
	eor.l %d0,%d5

	lsr.l %d7,%d3			/* des_SPtrans[7][(t>>26L)&0x3f] */
	lea des_SPtrans+1792,%a2
	move.l (%a2,%d3.l*4),%d3
	eor.l %d3,%d5

	/* ---- */

	add.l %a1,%a0			/* s += 2 */
	subq.l #1, %d6			/* i-- */
	jbge .L19


	move.l %d4,%d0
	move.l %d5,%d4
	move.l %d0,%d5
	/* ASSUME: d5=r=data[0], d4=l=data[1] */
	rts

/****************************************************************************/
