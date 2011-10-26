/****************************************************************************/

/*
 *	mips.h  --  common defines for MIPS platforms
 *
 *	(C) Copyright 2007, Greg Ungerer <gerg@snapgear.com>
 */

/****************************************************************************/
#ifndef mips_h
#define	mips_h
/****************************************************************************/

/*
 *	Register ABI definitions.
 */
#define	zero		$0		/* always reads as zero */
#define	at		$1		/* assembler temporary */
#define	v0		$2		/* function / expression eval */
#define	v1		$3
#define	a0		$4		/* function arguments */
#define	a1		$5
#define	a2		$6
#define	a3		$7
#define	t0		$8		/* temporaries */
#define	t1		$9
#define	t2		$10
#define	t3		$11
#define	t4		$12
#define	t5		$13
#define	t6		$14
#define	t7		$15
#define	s0		$16		/* saved temporaries */
#define	s1		$17
#define	s2		$18
#define	s3		$19
#define	s4		$20
#define	s5		$21
#define	s6		$22
#define	s7		$23
#define	t8		$24		/* temporaries */
#define	t9		$25
#define	k0		$26		/* resevred for OS */
#define	k1		$27
#define	gp		$28		/* global pointer */
#define	sp		$29		/* stack pointer */
#define	fp		$30		/* frame pointer */
#define	ra		$31		/* return address */

/****************************************************************************/
#endif /* mips_h */
