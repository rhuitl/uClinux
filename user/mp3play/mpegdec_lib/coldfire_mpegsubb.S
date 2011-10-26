//------------------------------------------------------------------------------
//
//   File    :   MPEGSUBB.a
//
//   Author  :   Stéphane TAVENARD
//
//   (C) Copyright 1997-1998 Stéphane TAVENARD
//       All Rights Reserved
//
//   #Rev|   Date   |                      Comment
//   ----|----------|--------------------------------------------------------
//   0   |10/04/1997| Initial revision                                     ST
//   1   |18/05/1997| Optimized windowing for '060                         ST
//   2   |01/11/1997| Use link instead of static vars                      ST
//   3   |08/04/1998| Use overflow optimization from ... (IRC man)         ST
//   4   |21/06/1998| Use external dewindow                                ST
//
//   ------------------------------------------------------------------------
//
//   MPEG SUBroutines optimized !
//
//------------------------------------------------------------------------------
               .globl     MPEGSUBB_antialias
               .globl     MPEGSUBB_filter_band
               .globl     MPEGSUBB_window_band

               .text

#define INT_FACTOR     14

#define ALIAS_BITS     15

#define IMMED #
#define IMM #
#define _IMM

#define DBRA(x,y) \
			   subq.l    IMM 1, x; \
			   jbge      y

/* I tried using the coldfire MAC unit to improve these and
 * it slowed things down.  Cycle counting indicated 10 without
 * the MAC and 9 with so there must be some fun stuff going on
 */
//
// ALIAS_U bu,csi,bd,cai,<tmp reg>,<reg>
// performs: (bu * csi) - (bd * cai) -> <reg>
// <tmp reg> is used for calculation
// d6 must be set to ALIAS_BITS
//
#define ALIAS_U(p1,p2,p3,p4,p5,p6)	\
		move.w	p1,p6;		\
		muls.w	IMM p2,p6;	\
		move.w	p3,p5;		\
		muls.w	IMM p4,p5;	\
		sub.l	p5,p6;		\
		asr.l	d6,p6

//
// ALIAS_D bd,csi,bu,cai,<tmp reg>,<reg>
// performs: (bd * csi) + (bu * cai) -> <reg>
// <tmp reg> is used for calculation
// d6 must be set to ALIAS_BITS
//
#define ALIAS_D(p1,p2,p3,p4,p5,p6)	\
		move.w	p1,p6;		\
		muls.w	IMM p2,p6;	\
		move.w	p3,p5;		\
		muls.w	IMM p4,p5;	\
		add.l	p5,p6;		\
		asr.l	d6,p6

#define bd             a1
#define bu             a2

//
// ALIAS_B csi,cai
// perform 1 alias butterfly
// uses d0..d3
//
#define ALIAS_B(p1,p2) \
               move.w   -(bu),d2 ; \
               move.w   (bd),d3 ; \
               ALIAS_U  (d2,p1,d3,p2,d0,d1) ; \
               move.w   d1,(bu) ; \
               ALIAS_D  (d3,p1,d2,p2,d0,d1) ; \
               move.w   d1,(bd)+

// Layer III antialiasing filter
//
// a0 = sample buffer xr (INT16)
// d0 = sblimit
//
MPEGSUBB_antialias:

               move.l   sp@(4), a0
               move.l   sp@(8), d0

	       sub.l    #28,sp
               movem.l  d2-d7/a2,(sp)
	       
	       clr.l	d7
	       move.w	d0,d7
               subq.l   #1,d7
               jbmi      antialias2
               clr.l    d5              // d5 =i = 0
               moveq.l  #ALIAS_BITS,d6  // for alias mult
antialias1:
               add.l    #18,d5          // i += SSLIMIT
               lea      (a0,d5.l*2),bu  // bu = xr[ i ]
               move.l   bu,bd           // bd = bu
               ALIAS_B  (_IMM 28098,_IMM -16858)
               ALIAS_B  (_IMM 28892,_IMM -15457)
               ALIAS_B  (_IMM 31117,_IMM -10268)
               ALIAS_B  (_IMM 32221,_IMM -5960)
               ALIAS_B  (_IMM 32621,_IMM -3099)
               ALIAS_B  (_IMM 32740,_IMM -1342)
               ALIAS_B  (_IMM 32764,_IMM -465)
               ALIAS_B  (_IMM 32767,_IMM -121)
               DBRA     (d7, antialias1)
antialias2:
               movem.l  (sp),d2-d7/a2
	       add.l    #28,sp
               rts



#define ps1            a3
#define ps2            a4
#define pd1            a5
//#define pd2            a6 // #2

//
//              Filter COS values for fast cosine transform
//
#define SH             1      // In order to preserve bits in multiply
#define SHIFT(x)       ((x)/2)
#define MUL_SHIFT      16-SH

#define COS1_64        0x4014 // 0x8028>>SH
#define COS3_64        0x40b3 // 0x8167>>SH
#define COS5_64        0x41fa // 0x83f4>>SH
#define COS7_64        0x43f9 // 0x87f2>>SH
#define COS9_64        0x46cc // 0x8d98>>SH
#define COS11_64       0x4a9d // 0x953b>>SH
#define COS13_64       0x4fae // 0x9f5c>>SH
#define COS15_64       0x5660 // 0xacc0>>SH
#define COS17_64       0x5f4d // 0xbe9a>>SH
#define COS19_64       0x6b70 // 0xd6e0>>SH
#define COS21_64       0x7c7d // 0xf8fa>>SH
#define COS23_64       0x95b0 // 0x12b60>>SH
#define COS25_64       0xbdf9 // 0x17bf2>>SH
#define COS27_64       0x10765 // 0x20ecb>>SH
#define COS29_64       0x1b42c // 0x36859>>SH
#define COS31_64       0x51852 // 0xa30a4>>SH
#define COS1_32        0x404f // 0x809f>>SH
#define COS3_32        0x42e1 // 0x85c2>>SH
#define COS5_32        0x4891 // 0x9123>>SH
#define COS7_32        0x52cb // 0xa596>>SH
#define COS9_32        0x64e2 // 0xc9c5>>SH
#define COS11_32       0x87c4 // 0x10f89>>SH
#define COS13_32       0xdc79 // 0x1b8f2>>SH
#define COS15_32       0x28cf2 // 0x519e5>>SH
#define COS1_16        0x4141 // 0x8282>>SH
#define COS3_16        0x4cf9 // 0x99f2>>SH
#define COS5_16        0x7332 // 0xe665>>SH
#define COS7_16        0x1480d // 0x2901b>>SH
#define COS1_8         0x4546 // 0x8a8c>>SH
#define COS3_8         0xa73d // 0x14e7b>>SH
#define COS1_4         0x5a82 // 0xb505>>SH

// Multiply an immediate constant with a register appropriately scaled
#define MUL32I(p1,p2)		\
	       move.l   p1, d5;	\
               muls.l   d5, p2;	\
               asr.l    d6, p2

// Multiply against a register with appropriate scaling
// We can do almost every addressing mode here except for immediate :-(
#define MUL32AM(p1,p2)		\
               muls.l   p1, p2;	\
               asr.l    d6, p2

#define FFF_MUL(p1,p2)			\
               move.l   (ps1)+,d0 ;	\
               move.l   d0,d1 ;		\
               move.l   -(ps2),d2 ;	\
               add.l    d2,d1 ;		\
               move.l   d1,(pd1)+ ;	\
               sub.l    d2,d0 ;		\
               MUL32I   (IMMED p1,d0) ;	\
               move.l   d0,p2*4-4(pd1)

//
//              FF4_MUL s1,s2,s3,s4
//              s1..s4 must be registers
//              d0, s1, s2 modified
//
//              s1 + s4 -> (pd1)+
//              s2 + s3 -> (pd1)+
//              (s1 - s4) * COS1_8 -> (pd1)+
//              (s2 - s3) * COS3_8 -> (pd1)+
//
#define FF4_MUL(p1,p2,p3,p4)			\
               move.l   p1,d0 ;			\
               add.l    p4,d0 ;			\
               move.l   d0,(pd1)+ ;		\
               move.l   p2,d0 ;			\
               add.l    p3,d0 ;			\
               move.l   d0,(pd1)+ ;		\
               sub.l    p4,p1 ;			\
               MUL32I   (IMMED COS1_8,p1) ;	\
               move.l   p1,(pd1)+ ;		\
               sub.l    p3,p2 ;			\
               MUL32I   (IMMED COS3_8,p2) ;	\
               move.l   p2,(pd1)+

//
//              FF2_MUL s1,s2,COSx
//              s1..s2, COSx must be registers
//              d0, s1 modified
//
//              s1 + s2 -> (pd1)+
//              (s1 - s2) * COSx -> (pd1)+
//
#define FF2_MUL(p1,p2,p3)		\
               move.l   p1,d0 ;		\
               add.l    p2,d0 ;		\
               move.l   d0,(pd1)+ ;	\
               sub.l    p2,p1 ;		\
               MUL32AM  (p3,p1) ;	\
               move.l   p1,(pd1)+

fast_filter_sub:
//               lea      filter_p,ps1   // ps1=@p(0)
               lea      -32*4(a6),ps1   // ps1=@p(0)
               lea      16*4(ps1),ps2  // ps2=@p(16)
//               lea      filter_pp,pd1  // pd1=@pp(0)
               lea      -16*4(a6),pd1  // pd1=@pp(0)
               FFF_MUL  (COS1_32,8)      // pp(i=0..7)  = p(i) + p(15-i)
               FFF_MUL  (COS3_32,8)      // pp(i=8..15) = COSx*[p(i) - p(15-i)]
               FFF_MUL  (COS5_32,8)
               FFF_MUL  (COS7_32,8)
               FFF_MUL  (COS9_32,8)
               FFF_MUL  (COS11_32,8)
               FFF_MUL  (COS13_32,8)
               FFF_MUL  (COS15_32,8)

//               lea      filter_pp,ps1  // ps1=@pp(0)
               lea      -16*4(a6),ps1  // ps1=@pp(0)
               lea      8*4(ps1),ps2   // ps2=@pp(8)
//               lea      filter_p,pd1   // pd1=@p(0)
               lea      -32*4(a6),pd1   // pd1=@p(0)
               FFF_MUL  (COS1_16,4)     // p(i=0..3) = pp(i) + pp(7-i)
               FFF_MUL  (COS3_16,4)     // p(i=4..7) = COSx*[pp(i) - pp(7-i)]
               FFF_MUL  (COS5_16,4)
               FFF_MUL  (COS7_16,4)
               lea      4*4(ps1),ps1   // ps1=@pp(8)
               lea      8*4(ps1),ps2   // ps2=@pp(16)
               lea      4*4(pd1),pd1   // pd1=@p(8)
               FFF_MUL  (COS1_16,4)
               FFF_MUL  (COS3_16,4)
               FFF_MUL  (COS5_16,4)
               FFF_MUL  (COS7_16,4)

//               lea      filter_p,ps1   // ps1=@p(0)
               lea      -32*4(a6),ps1   // ps1=@p(0)
//               lea      filter_pp,pd1  // pd1=@pp(0)
               lea      -16*4(a6),pd1  // pd1=@pp(0)
	       move.l	(ps1)+, d1	// get p0..p3
	       move.l	(ps1)+, d2
	       move.l	(ps1)+, d3
	       move.l	(ps1)+, d4
               FF4_MUL  (d1,d2,d3,d4)
	       move.l	(ps1)+, d1	// get p4..p7
	       move.l	(ps1)+, d2
	       move.l	(ps1)+, d3
	       move.l	(ps1)+, d4
               FF4_MUL  (d1,d2,d3,d4)
	       move.l	(ps1)+, d1	// get p8..p11
	       move.l	(ps1)+, d2
	       move.l	(ps1)+, d3
	       move.l	(ps1)+, d4
               FF4_MUL  (d1,d2,d3,d4)
	       move.l	(ps1)+, d1	// get p12..p15
	       move.l	(ps1)+, d2
	       move.l	(ps1)+, d3
	       move.l	(ps1)+, d4
               FF4_MUL  (d1,d2,d3,d4)

//               lea      filter_pp,ps1  // ps1=@pp(0)
               lea      -16*4(a6),ps1  // ps1=@pp(0)
//               lea      filter_p,pd1   // pd1=@p(0)
               lea      -32*4(a6),pd1   // pd1=@p(0)
               move.l   #COS1_4,d3
               move.l  #8-1,d4
fast_filter_s2:
	       move.l	(ps1)+, d1
	       move.l	(ps1)+, d2
               FF2_MUL  (d1,d2,d3)
               DBRA     (d4,fast_filter_s2)

               rts

//
// GET_P <index> <dest ea>
// copy p[ index ] into a destination <ea>
// p is ps1
//
#define GET_P(p1,p2) move.l   p1*4(ps1),p2

//
// ADD_P <index> <dest ea>
// add p[ index ] to a destination <ea>
// p is ps1
//
#define ADD_P(p1,p2) add.l    p1*4(ps1),p2

//
// SET_S0 <index> <src ea>
// copy a source <ea> into s0[ index ]
// s0 is a1
//

#define SET_S0(p1,p2) \
		move.l   d0, -(sp); \
		move.w   p2, d0; \
		move.w   d0,p1*2*16(a1); \
		move.l 	(sp)+, d0

//
// SET_S1 <index> <src ea>
// copy a source <ea> into s1[ index ]
// s1 is a2
//
#define SET_S1(p1,p2) move.w   p2,p1*2*16(a2)

//
// SET_S0_P <index> <src reg>
// copy <reg>  into s0[ index ]
// copy -<reg> into s0[ 32-index ]
// s0 is a1
// <reg> is modified
//
#define SET_S0_P(p1,p2) \
               move.w   p2,p1*2*16(a1) ; \
               neg.l    p2 ; \
               move.w   p2,-p1*2*16+1024(a1)

//
// SET_S1_P <index> <src reg>
// copy -<reg> into s1[ index ]
// copy -<reg> into s1[ 32-index ]
// s1 is a2
// <reg> is modified
//
#define SET_S1_P(p1,p2) \
               neg.l    p2 ; \
               move.w   p2,p1*2*16(a2) ; \
               move.w   p2,-p1*2*16+1024(a2)

//              Apply the FAST synthesis filter to a sub band
//              Generate full frequency sample
//
//              a0: bandPtr (=fraction)
//              a1: out_filter_buffer 0
//              a2: out_filter_buffer 1
//              d0.w: freq_div // #2
//
// registers allocation: d6=MUL_SHIFT
//
MPEGSUBB_filter_band:

               move.l   sp@(4), a0
               move.l   sp@(8), a1
               move.l   sp@(12), d1
               move.l   sp@(16), d0
	       ext.l	d0

			   sub.l    #44, sp
               movem.l  d2-d7/a2-a6,(sp)

			   move.l   d1, a2
               move.l   d0,d7 // #2

               link     a6,#-32*4      // #2 need of 2*16 longs

               moveq.l  #MUL_SHIFT,d6  // For MUL32 normalize shift

               move.l   a0,ps1         // ps1=fraction(0)
               lea      32*2(ps1),ps2  // ps2=fraction(32)
//               lea      filter_p,pd1   // pd1=@p(0)
               lea      -32*4(a6),pd1  // pd1=@p(0)

//               move.w   freq_div,d0
//               cmp.w    #4,d0
               cmp.l    #4,d7 // #2
               jbne      filter_band1
               // Filter only 1/4 freq
               move.l  #8-1,d2
filter_band_q1:                                            // p(i=0..7) = f(i)
               move.w   (ps1)+,d0
               ext.l    d0
               move.l   d0,(pd1)+
               DBRA     (d2,filter_band_q1)

//               lea      filter_p,ps1   // ps1=@p(0)
               lea      -32*4(a6),ps1   // ps1=@p(0)
               lea      8*4(ps1),ps2   // ps2=@p(8)
//               lea      filter_pp,pd1  // pd1=@pp(0)
               lea      -16*4(a6),pd1  // pd1=@pp(0)
               FFF_MUL  (COS1_16,4)      // pp(i=0..3) = p(i) + p(7-i)
               FFF_MUL  (COS3_16,4)      // pp(i=4..7) = COSx*[p(i) - p(7-i)]
               FFF_MUL  (COS5_16,4)
               FFF_MUL  (COS7_16,4)

//               lea      filter_pp,ps1  // ps1=@pp(0)
               lea      -16*4(a6),ps1  // ps1=@pp(0)
//               lea      filter_p,pd1   // pd1=@p(0)
               lea      -32*4(a6),pd1   // pd1=@p(0)
	       move.l	(ps1)+, d1	// get pp0..pp3
	       move.l	(ps1)+, d2
	       move.l	(ps1)+, d3
	       move.l	(ps1)+, d4
               FF4_MUL  (d1,d2,d3,d4)
	       move.l	(ps1)+, d1	// get pp4..pp7
	       move.l	(ps1)+, d2
	       move.l	(ps1)+, d3
	       move.l	(ps1)+, d4
               FF4_MUL  (d1,d2,d3,d4)

//               lea      filter_p,ps1   // ps1=@p(0)
               lea      -32*4(a6),ps1   // ps1=@p(0)
//               lea      filter_p,pd1   // pd1=@p(0)
               lea      -32*4(a6),pd1   // pd1=@p(0)
               move.l   #COS1_4,d3
               move.l  #4-1,d4
fast_filter_q2:
	       move.l	(ps1)+,d1
	       move.l	(ps1)+,d2
               FF2_MUL  (d1,d2,d3)
               DBRA     (d4,fast_filter_q2)

//               lea      filter_p,ps1   // ps1=@p(0)
               lea      -32*4(a6),ps1   // ps1=@p(0)

               GET_P    (1,d1)
               SET_S0   (0,d1)
               neg.l    d1
               SET_S1   (0,d1)

               GET_P    (5,d1)
               ADD_P    (7,d1)
               SET_S0_P (4,d1)

               GET_P    (3,d1)
               SET_S0_P (8,d1)

               GET_P    (7,d1)
               SET_S0_P (12,d1)

               SET_S0   (16,#0)

               GET_P    (6,d3)
               ADD_P    (7,d3)

               move.l   d3,d4
               ADD_P    (5,d4)
               SET_S1_P (4,d4)

               GET_P    (2,d4)
               ADD_P    (3,d4)
               SET_S1_P (8,d4)

               move.l   d3,d4
               ADD_P    (4,d4)
               SET_S1_P (12,d4)

               GET_P    (0,d4)
               neg.l    d4
               SET_S1   (16,d4)

               jbra      filter_band9

filter_band1:
//               cmp.w    #2,d0
               cmp.l    #2,d7 // #2
               jbne      filter_band2
               // Filter only 1/2 freq
               move.l  #16-1,d2
filter_band_h1:                                             // p(i=0..15) = f(i)
               move.w   (ps1)+,d0
               ext.l    d0
               move.l   d0,(pd1)+
               DBRA     (d2,filter_band_h1)
               jbra      filter_band3

filter_band2:
               // Filter full freq
               move.l  #16-1,d2
filter_band_f1:                         // p(i=0..15) = f(i) + f(31-i)
               move.w   (ps1)+,d0
               move.w   -(ps2),d1
               ext.l    d0
               ext.l    d1
               add.l    d0,d1
               move.l   d1,(pd1)+
               DBRA     (d2,filter_band_f1)
filter_band3:
               jbsr      fast_filter_sub

//               lea      filter_p,ps1   // ps1=@p(0)
               lea      -32*4(a6),ps1   // ps1=@p(0)

               GET_P    (13,d0)
               ADD_P    (15,d0)

               GET_P    (1,d1)
               SET_S0   (0,d1)
               neg.l    d1
               SET_S1   (0,d1)

               move.l   d0,d1
               ADD_P    (9,d1)
               SET_S0_P (2,d1)

               GET_P    (5,d1)
               ADD_P    (7,d1)
               SET_S0_P (4,d1)

               move.l   d0,d1
               ADD_P    (11,d1)
               SET_S0_P (6,d1)

               GET_P    (3,d1)
               SET_S0_P (8,d1)

               GET_P    (11,d1)
               ADD_P    (15,d1)
               SET_S0_P (10,d1)

               GET_P    (7,d1)
               SET_S0_P (12,d1)

               GET_P    (15,d1)
               SET_S0_P (14,d1)

               SET_S0   (16,#0)


               ADD_P    (14,d0)
               GET_P    (12,d1)
               ADD_P    (14,d1)
               ADD_P    (15,d1)
               GET_P    (10,d2)
               ADD_P    (11,d2)
               GET_P    (6,d3)
               ADD_P    (7,d3)

               move.l   d0,d4
               ADD_P    (9,d4)
               SET_S1_P (2,d4)

               move.l   d3,d4
               ADD_P    (5,d4)
               SET_S1_P (4,d4)

               move.l   d0,d4
               add.l    d2,d4
               SET_S1_P (6,d4)

               GET_P    (2,d4)
               ADD_P    (3,d4)
               SET_S1_P (8,d4)

               move.l   d1,d4
               add.l    d2,d4
               SET_S1_P (10,d4)

               move.l   d3,d4
               ADD_P    (4,d4)
               SET_S1_P (12,d4)

               move.l   d1,d4
               ADD_P    (8,d4)
               SET_S1_P (14,d4)

               GET_P    (0,d4)
               neg.l    d4
               SET_S1   (16,d4)

//               move.w   freq_div,d0
//               cmp.w    #1,d0
               cmp.l    #1,d7 // #2
               jbne      filter_band9

               move.l   a0,ps1         // ps1=fraction(0)
               lea      32*2(ps1),ps2  // ps2=fraction(32)
//               lea      filter_p,pd1   // pd1=@p(0)
               lea      -32*4(a6),pd1   // pd1=@p(0)

               lea      pc@(filter_cos64),a0
               move.l   #16-1,d2
filter_band_f2:                         // p(i=0..15) = COSx*[f(i) - f(31-i)]
               move.w   (ps1)+,d0
               move.w   -(ps2),d1
               ext.l    d0
               ext.l    d1
               sub.l    d1,d0
               MUL32AM  ((a0)+,d0)
               move.l   d0,(pd1)+
               DBRA     (d2,filter_band_f2)

               jbsr      fast_filter_sub

//               lea      filter_p,ps1   // ps1=@p(0)
               lea      -32*4(a6),ps1   // ps1=@p(0)

               GET_P    (13,d0)
               ADD_P    (15,d0)
               GET_P    (11,d1)
               ADD_P    (15,d1)
               GET_P    (5,d2)
               ADD_P    (7,d2)

               move.l   d0,d3
               ADD_P    (9,d3)
               move.l   d3,d4
               ADD_P    (1,d4)
               SET_S0_P (1,d4)

               move.l   d2,d4
               add.l    d3,d4
               SET_S0_P (3,d4)

               move.l   d0,d3
               ADD_P    (11,d3)
               move.l   d3,d4
               add.l    d2,d4
               SET_S0_P (5,d4)

               move.l   d3,d4
               ADD_P    (3,d4)
               SET_S0_P (7,d4)

               move.l   d1,d4
               ADD_P    (3,d4)
               SET_S0_P (9,d4)

               move.l   d1,d4
               ADD_P    (7,d4)
               SET_S0_P (11,d4)

               GET_P    (7,d4)
               ADD_P    (15,d4)
               SET_S0_P (13,d4)

               GET_P    (15,d4)
               SET_S0_P (15,d4)


               ADD_P    (14,d0)
               GET_P    (12,d1)
               ADD_P    (14,d1)
               ADD_P    (15,d1)
               GET_P    (10,d2)
               ADD_P    (11,d2)
               GET_P    (6,d3)
               ADD_P    (7,d3)

               GET_P    (1,d4)
               ADD_P    (9,d4)
               add.l    d0,d4
               SET_S1_P (1,d4)

               GET_P    (5,d5)
               add.l    d3,d5
               add.l    d0,d5
               GET_P    (9,d4)
               add.l    d5,d4
               SET_S1_P (3,d4)

               move.l   d5,d4
               add.l    d2,d4
               SET_S1_P (5,d4)

               GET_P    (2,d5)
               ADD_P    (3,d5)
               add.l    d2,d5
               move.l   d0,d4
               add.l    d5,d4
               SET_S1_P (7,d4)

               move.l   d1,d4
               add.l    d5,d4
               SET_S1_P (9,d4)

               GET_P    (4,d5)
               add.l    d3,d5
               add.l    d1,d5
               move.l   d2,d4
               add.l    d5,d4
               SET_S1_P (11,d4)

               GET_P    (8,d4)
               add.l    d5,d4
               SET_S1_P (13,d4)

               GET_P    (0,d4)
               ADD_P    (8,d4)
               add.l    d1,d4
               SET_S1_P (15,d4)

filter_band9:
               unlk     a6    // #2
               movem.l  (sp),d2-d7/a2-a6
			   add.l	#44,sp
               rts



filter_cos64:
               dc.l     COS1_64, COS3_64, COS5_64, COS7_64
               dc.l     COS9_64, COS11_64, COS13_64, COS15_64
               dc.l     COS17_64, COS19_64, COS21_64, COS23_64
               dc.l     COS25_64, COS27_64, COS29_64, COS31_64

               // #2 Begin
               // pcm_loops[ freq_div ] = = (32 / freq_div) - 1
pcm_loops:     dc.w     0, 31, 15, 9, 7, 0

               // #2 End


#define WINDOW_CLIP    1

//
//              Window a sub band filtered sample
//
//              a0: out_filter_buffer
//              a1: out_sample_buffer
//              a2: dewindow (##4)
//              d0: buffer offset
//              d1.w: w_begin  (#2)
//              d2.w: w_width  (#2)
//              d3.w: freq_div (#2)
//              d4.l: dew_shift (##4)
//              -> a1 = out_sample_buffer + out_sample_length
MPEGSUBB_window_band:

			   sub.l	#44, sp
               movem.l  d2-d7/a2-a6,(sp)

	       move.l	sp@(48), a0
	       move.l	sp@(52), a1
	       move.l	sp@(56), a2
	       move.l	sp@(60), d0
	       move.l	sp@(64), d1
	       move.l	sp@(68), d2
	       move.l	sp@(72), d3
	       move.l	sp@(76), d4
	       ext.l	d1
	       ext.l	d2
	       ext.l	d3

//               move.w   w_begin,d1 // #2
               move.l   d2,-(sp) // #2
               move.l   a2,a4    // ##4
               lea.l    pc@(pcm_loops),a2 // #2
               move.w   (a2,d3.l*2),d6 // #2
	       ext.l	d6
               move.l   d3,d2 // #2

//               lea.l    window_table,a2     //  ##4 External now
               lea.l    (a4,d1.l*2),a2       //  ##4 a2 = &dewindow[ w_begin ]
               moveq.l  # INT_FACTOR-15,d7    //  ##4 External now
               add.l    d4,d7                //  ##4 new scale
               add.l    d0,d1
               and.l    #15,d1               // d1 = start
               move.l   a0,a4                // buf0 = &buf_ptr[ 0 ]
               lea      (a0,d1.l*2),a3       // buf1 = &buf_ptr[ start ]
//               move.w   w_width,d3 // #2
               move.l   (sp),d3 // #2
               add.l    d1,d3
			   ext.l    d3
               cmp.l    #16,d3
               jble      window_band1
               move.l   #16,d3               // d3 = top
window_band1:
               sub.l    d1,d3                // d3 = cnt1
//               move.w   w_width,d4  // #2
               move.l   (sp),d4 // #2
			   ext.l    d4
               sub.l    d3,d4                // d4 = cnt0

//               move.w   freq_div,d2 // #2
               lsl.l    #4,d2
               move.l   d2,d5
               sub.l    d3,d5                // off1 = freq_div*16 - cnt1
               ext.l    d5
               add.l    d5,d5
               move.l   d5,a5                // a5 = off1
               move.l   d2,d5
               sub.l    d4,d5                // off0 = freq_div*16 - cnt0
               add.l    d5,d5
               move.l   d5,a6                // a6 = off0
//               sub.w    w_width,d2           // offd = freq_div*16 - w_width (#2)
               sub.l    (sp),d2                // offd = freq_div*16 - w_width (#2)
               ext.l    d2
               add.l    d2,d2

//               moveq.l  # WINDOW_FACTOR+INT_FACTOR-15,d7 // ##4 External now
//               move.w   pcm_count,d6  // #2
//               subq.w   #1,d6         // for DBRA loop ; #2


#define MULADDN(p1, p2) jbsr      mulladdwin_ ## p1 ## _ ## p2

#ifdef COLDFIRE_MAC

/* This code isn't really set up for using the coldfire MAC unit.
 * It would be better if the in memory data items were all in .l format
 * then the macl instruction suite could be used to decrease execution
 * time fairly impressively.
 */
// The mac instruction in this one is "mac.w d5l, d1l"
#define MULADDWIN(p1)		\
	move.w	(p1)+, d1;	\
	move.w	(a2)+, d5;	\
	dc.w	0xa205;		\
	dc.w	0x0000

//              MULADD0 <rept num>
// The mac instruction here is "move.l #0, acc"
#define MULADD0(p1)			\
               dc.w	0xa13c;		\
	       dc.l	0;		\
               MULADDN  (a3,p1)

//              MULADD1 <rept num>
// The mac instruction here is "move.l acc, d5"
#define MULADD1(p1)			\
               add.l    a5,a3;		\
               MULADDN  (a4,p1);	\
	       dc.w	0xa185

#else					// ! COLDFIRE_MAC
//              MULADDWIN {a3|a4}
#define MULADDWIN(p1)			\
               move.w   (p1)+,d1;	\
               muls.w   (a2)+,d1;	\
               add.l    d1,d5


//              MULADD0 <rept num>
#define MULADD0(p1)			\
               clr.l    d5;		\
               MULADDN  (a3,p1)

//              MULADD1 <rept num>
#define MULADD1(p1)			\
               add.l    a5,a3;		\
               MULADDN  (a4,p1)
#endif					// COLDFIRE_MAC

               // CHECKBOUNDS <loop label>
#ifdef WINDOW_CLIP
#define CHECKBOUNDS(p1) \
               add.l    a6,a4; \
               add.l    d2,a2; \
               asr.l    d7,d5; \
               move.w   d5,a0; \
               cmp.l    a0,d5; \
               bne.b    2f; \
1: \
               move.w   d5,(a1)+; \
               DBRA     (d6,p1); \
               jbra      window_band9; \
2: \
               not.l    d5; \
               add.l    d5,d5; \
               move.l   IMMED 0xFFFF8000,d5; \
               negx.l   d5; \
               bra.s    1b; \
/*             move.w   d5,(a1)+; */ \
/*             DBRA     (d6,p1); */ \
/*             bra      window_band9; */

#else /* WINDOW_CLIP */

#define CHECKBOUNDS(p1) \
               add.l    a6,a4; \
               add.l    d2,a2; \
               asr.l    d7,d5; \
               move.w   d5,(a1)+; \
               DBRA     (d6,p1); \
               jbra      window_band9

#endif /* WINDOW_CLIP */


//               move.w   w_width,d3 // #2
               move.l   (sp),d3 // #2
	       ext.l	d3
               lea      pc@(window_q0muls),a0
               cmp.l    #4,d3
               jble      window_qmul
               lea      pc@(window_q1muls),a0
               cmp.l    #8,d3
               jble      window_qmul
               lea      pc@(window_q2muls),a0
window_qmul:
               move.l   (a0,d4.l*4),a0
               jmp      (pc,a0)

window_q2mul0:
               MULADD0  (16)
               MULADD1  (0)
               CHECKBOUNDS (window_q2mul0)
window_q2mul1:
               MULADD0  (15)
               MULADD1  (1)
               CHECKBOUNDS (window_q2mul1)
window_q2mul2:
               MULADD0  (14)
               MULADD1  (2)
               CHECKBOUNDS (window_q2mul2)
window_q2mul3:
               MULADD0  (13)
               MULADD1  (3)
               CHECKBOUNDS (window_q2mul3)
window_q2mul4:
               MULADD0  (12)
               MULADD1  (4)
               CHECKBOUNDS (window_q2mul4)
window_q2mul5:
               MULADD0  (11)
               MULADD1  (5)
               CHECKBOUNDS (window_q2mul5)
window_q2mul6:
               MULADD0  (10)
               MULADD1  (6)
               CHECKBOUNDS (window_q2mul6)
window_q2mul7:
               MULADD0  (9)
               MULADD1  (7)
               CHECKBOUNDS (window_q2mul7)
window_q2mul8:
               MULADD0  (8)
               MULADD1  (8)
               CHECKBOUNDS (window_q2mul8)
window_q2mul9:
               MULADD0  (7)
               MULADD1  (9)
               CHECKBOUNDS (window_q2mul9)
window_q2mul10:
               MULADD0  (6)
               MULADD1  (10)
               CHECKBOUNDS (window_q2mul10)
window_q2mul11:
               MULADD0  (5)
               MULADD1  (11)
               CHECKBOUNDS (window_q2mul11)
window_q2mul12:
               MULADD0  (4)
               MULADD1  (12)
               CHECKBOUNDS (window_q2mul12)
window_q2mul13:
               MULADD0  (3)
               MULADD1  (13)
               CHECKBOUNDS (window_q2mul13)
window_q2mul14:
               MULADD0  (2)
               MULADD1  (14)
               CHECKBOUNDS (window_q2mul14)
window_q2mul15:
               MULADD0  (1)
               MULADD1  (15)
               CHECKBOUNDS (window_q2mul15)

window_q1mul0:
               MULADD0  (8)
               MULADD1  (0)
               CHECKBOUNDS (window_q1mul0)
window_q1mul1:
               MULADD0  (7)
               MULADD1  (1)
               CHECKBOUNDS (window_q1mul1)
window_q1mul2:
               MULADD0  (6)
               MULADD1  (2)
               CHECKBOUNDS (window_q1mul2)
window_q1mul3:
               MULADD0  (5)
               MULADD1  (3)
               CHECKBOUNDS (window_q1mul3)
window_q1mul4:
               MULADD0  (4)
               MULADD1  (4)
               CHECKBOUNDS (window_q1mul4)
window_q1mul5:
               MULADD0  (3)
               MULADD1  (5)
               CHECKBOUNDS (window_q1mul5)
window_q1mul6:
               MULADD0  (2)
               MULADD1  (6)
               CHECKBOUNDS (window_q1mul6)
window_q1mul7:
               MULADD0  (1)
               MULADD1  (7)
               CHECKBOUNDS (window_q1mul7)

window_q0mul0:
               MULADD0  (4)
               MULADD1  (0)
               CHECKBOUNDS (window_q0mul0)
window_q0mul1:
               MULADD0  (3)
               MULADD1  (1)
               CHECKBOUNDS (window_q0mul1)
window_q0mul2:
               MULADD0  (2)
               MULADD1  (2)
               CHECKBOUNDS (window_q0mul2)
window_q0mul3:
               MULADD0  (1)
               MULADD1  (3)
               CHECKBOUNDS (window_q0mul3)

window_band9:
               move.l   (sp)+,d2
               movem.l  (sp),d2-d7/a2-a6
	       add.l    #44, sp
               rts

mulladdwin_a3_16: MULADDWIN(a3)
mulladdwin_a3_15: MULADDWIN(a3)
mulladdwin_a3_14: MULADDWIN(a3)
mulladdwin_a3_13: MULADDWIN(a3)
mulladdwin_a3_12: MULADDWIN(a3)
mulladdwin_a3_11: MULADDWIN(a3)
mulladdwin_a3_10: MULADDWIN(a3)
mulladdwin_a3_9:  MULADDWIN(a3)
mulladdwin_a3_8:  MULADDWIN(a3)
mulladdwin_a3_7:  MULADDWIN(a3)
mulladdwin_a3_6:  MULADDWIN(a3)
mulladdwin_a3_5:  MULADDWIN(a3)
mulladdwin_a3_4:  MULADDWIN(a3)
mulladdwin_a3_3:  MULADDWIN(a3)
mulladdwin_a3_2:  MULADDWIN(a3)
mulladdwin_a3_1:  MULADDWIN(a3)
mulladdwin_a3_0:  rts

mulladdwin_a4_16: MULADDWIN(a4)
mulladdwin_a4_15: MULADDWIN(a4)
mulladdwin_a4_14: MULADDWIN(a4)
mulladdwin_a4_13: MULADDWIN(a4)
mulladdwin_a4_12: MULADDWIN(a4)
mulladdwin_a4_11: MULADDWIN(a4)
mulladdwin_a4_10: MULADDWIN(a4)
mulladdwin_a4_9:  MULADDWIN(a4)
mulladdwin_a4_8:  MULADDWIN(a4)
mulladdwin_a4_7:  MULADDWIN(a4)
mulladdwin_a4_6:  MULADDWIN(a4)
mulladdwin_a4_5:  MULADDWIN(a4)
mulladdwin_a4_4:  MULADDWIN(a4)
mulladdwin_a4_3:  MULADDWIN(a4)
mulladdwin_a4_2:  MULADDWIN(a4)
mulladdwin_a4_1:  MULADDWIN(a4)
mulladdwin_a4_0:  rts


/* Lookup table to allow us to dispatch into the above pile
 * of procedures easily.  These are stored PC relative from the
 * branch instruction before the window_q2mul0 label which means
 * we can pack this lot into the text segment and thus reduce
 * data size a little.
 */
window_q2muls: dc.l     window_q2mul0 - window_q2mul0 + 2
               dc.l     window_q2mul1 - window_q2mul0 + 2
               dc.l     window_q2mul2 - window_q2mul0 + 2
               dc.l     window_q2mul3 - window_q2mul0 + 2
               dc.l     window_q2mul4 - window_q2mul0 + 2
               dc.l     window_q2mul5 - window_q2mul0 + 2
               dc.l     window_q2mul6 - window_q2mul0 + 2
               dc.l     window_q2mul7 - window_q2mul0 + 2
               dc.l     window_q2mul8 - window_q2mul0 + 2
               dc.l     window_q2mul9 - window_q2mul0 + 2
               dc.l     window_q2mul10 - window_q2mul0 + 2
               dc.l     window_q2mul11 - window_q2mul0 + 2
               dc.l     window_q2mul12 - window_q2mul0 + 2
               dc.l     window_q2mul13 - window_q2mul0 + 2
               dc.l     window_q2mul14 - window_q2mul0 + 2
               dc.l     window_q2mul15 - window_q2mul0 + 2

window_q1muls: dc.l     window_q1mul0 - window_q2mul0 + 2
               dc.l     window_q1mul1 - window_q2mul0 + 2
               dc.l     window_q1mul2 - window_q2mul0 + 2
               dc.l     window_q1mul3 - window_q2mul0 + 2
               dc.l     window_q1mul4 - window_q2mul0 + 2
               dc.l     window_q1mul5 - window_q2mul0 + 2
               dc.l     window_q1mul6 - window_q2mul0 + 2
               dc.l     window_q1mul7 - window_q2mul0 + 2

window_q0muls: dc.l     window_q0mul0 - window_q2mul0 + 2
               dc.l     window_q0mul1 - window_q2mul0 + 2
               dc.l     window_q0mul2 - window_q2mul0 + 2
               dc.l     window_q0mul3 - window_q2mul0 + 2
