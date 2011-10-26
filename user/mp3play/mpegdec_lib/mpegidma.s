;------------------------------------------------------------------------------
;
;   File    :   MPEGIMDA.a
;
;   Author  :   Stéphane TAVENARD
;
;   $VER:   MPEGIMDA.a  0.1  (10/05/1997)
;
;   (C) Copyright 1997-1997 Stéphane TAVENARD
;       All Rights Reserved
;
;   #Rev|   Date   |                      Comment
;   ----|----------|--------------------------------------------------------
;   0   |04/03/1997| Initial revision                                     ST
;   1   |10/05/1997| use of link instead of static vars                   ST
;
;   ------------------------------------------------------------------------
;
;   MPEG IMDCT optimized !
;
;------------------------------------------------------------------------------

               XDEF     @MPEGIMDA_hybrid
               XDEF     _MPEGIMDA_hybrid

               section  ASMCODE,code

IMDCT_BITS     equ      14

;              Perform an IMDCT
;
;              a0:  in array (16-bit)
;              a1:  out array (16-bit)
;              a2:  prev block (16-bit)
;              d0.w: block type
;              d1.w: mixed (0 or 1)
;              d2.w: sb_max
;
@MPEGIMDA_hybrid
_MPEGIMDA_hybrid
               movem.l  d2-d7/a2-a6,-(sp)

               move.l   a2,a3    ; a3 = prev block

               clr.w    d5

               tst.w    d1
               beq      MPEGIMDA_h1
               ; mixed -> sb 0 & 1 to win 0
               lea      imdct_win0,a2
               movem.w  d0/d2,-(sp)
               bsr      imdct_l
               movem.w  (sp)+,d0/d2
               add.l    #2*18,a0    ; in += 18
               addq.l   #2,a1       ; out++;
               add.l    #2*18,a3    ; prev += 18
               addq.w   #1,d5
               cmp.w    d2,d5
               bge      MPEGIMDA_h5 ; end of imdct
               lea      imdct_win0_odd,a2
               movem.w  d0/d2,-(sp)
               bsr      imdct_l
               movem.w  (sp)+,d0/d2
               add.l    #2*18,a0    ; in += 18
               addq.l   #2,a1       ; out++;
               add.l    #2*18,a3    ; prev += 18
               addq.w   #1,d5
               cmp.w    d2,d5
               bge      MPEGIMDA_h5 ; end of imdct
MPEGIMDA_h1
               cmp.w    #2,d0
               beq      MPEGIMDA_h3 ; short blocks

               ; Long blocks
MPEGIMDA_h2
               lea      imdct_win,a2
               move.l   (a2,d0.w*4),a2
               movem.w  d0/d2,-(sp)
               bsr      imdct_l
               movem.w  (sp)+,d0/d2
               add.l    #2*18,a0    ; in += 18
               addq.l   #2,a1       ; out++;
               add.l    #2*18,a3    ; prev += 18
               addq.w   #1,d5
               cmp.w    d2,d5
               bge      MPEGIMDA_h5 ; end of imdct
               lea      imdct_win_odd,a2
               move.l   (a2,d0.w*4),a2
               movem.w  d0/d2,-(sp)
               bsr      imdct_l
               movem.w  (sp)+,d0/d2
               add.l    #2*18,a0    ; in += 18
               addq.l   #2,a1       ; out++;
               add.l    #2*18,a3    ; prev += 18
               addq.w   #1,d5
               cmp.w    d2,d5
               bge      MPEGIMDA_h5 ; end of imdct
               bra      MPEGIMDA_h2

               ; Short blocks
MPEGIMDA_h3
               lea      imdct_win2,a2
               movem.w  d0/d2,-(sp)
               bsr      imdct_s
               movem.w  (sp)+,d0/d2
               add.l    #2*18,a0    ; in += 18
               addq.l   #2,a1       ; out++;
               add.l    #2*18,a3    ; prev += 18
               addq.w   #1,d5
               cmp.w    d2,d5
               bge      MPEGIMDA_h5 ; end of imdct
               lea      imdct_win2_odd,a2
               movem.w  d0/d2,-(sp)
               bsr      imdct_s
               movem.w  (sp)+,d0/d2
               add.l    #2*18,a0    ; in += 18
               addq.l   #2,a1       ; out++;
               add.l    #2*18,a3    ; prev += 18
               addq.w   #1,d5
               cmp.w    d2,d5
               bge      MPEGIMDA_h5 ; end of imdct
               bra      MPEGIMDA_h3

               ; End of imdct -> overlap with 0 rest of bands
MPEGIMDA_h5
               cmp.w    #32,d5
               bge      MPEGIMDA_h7
               clr.l    d1
MPEGIMDA_h6
               move.w   (a3),0*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),1*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),2*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),3*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),4*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),5*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),6*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),7*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),8*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),9*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),10*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),11*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),12*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),13*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),14*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),15*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),16*2*32(a1)
               move.w   d1,(a3)+
               move.w   (a3),17*2*32(a1)
               move.w   d1,(a3)+
               addq.l   #2,a1    ; out++
               addq.w   #1,d5
               cmp.w    #32,d5
               blt      MPEGIMDA_h6

MPEGIMDA_h7
               movem.l  (sp)+,d2-d7/a2-a6
               rts

#define	K0      16368
#define	K1      16244
#define	K2      15996
#define	K3      15626
#define	K4      15137
#define	K5      14533
#define	K6      13818
#define	K7      12998
#define	K8      12080
#define	K9      11069
#define	K10      9974
#define	K11      8803
#define	K12      7565
#define	K13      6270
#define	K14      4927
#define	K15      3546
#define	K16      2139
#define	K17      715

#define	MUL32	muls.l $$1,$$2 \
		asr.l	%d6,$$2
		
#if 0	
MUL32          MACRO
               muls.l   \1,\2       ; ##7
               asr.l    d6,\2       ; ##7
               ENDM
#endif
/*	
;              S   a, <dummy reg>, <dest reg>
;              performs: (INT32)x[ a ] - (INT32)x[ 11-a ] - (INT32)x[ 12+a ]
;
*/	
#if 0	
S              MACRO
               move.w   \1*2(a0),\3
               ext.l    \3
               move.w   22-\1*2(a0),\2
               ext.l    \2
               sub.l    \2,\3
               move.w   24+\1*2(a0),\2
               ext.l    \2
               sub.l    \2,\3
               ENDM
#else
#define S      move.w   $$1*2(%a0),$$3 \
               ext.l    $$3 \
               move.w   22-$$1*2(%a0),$$2 \
               ext.l    $$2 \
               sub.l    $$2,$$3 \
               move.w   24+$$1*2(%a0),%%2 \
               ext.l    $$2
               sub.l    $$2,$$3
#endif
#if 0
;              M   xi, Kx, <dest reg>
;              performs: ((INT32)x[ xi ] * (Kx))
;
M              MACRO
               move.w   \1*2(a0),\3
               muls.w   #\2,\3
               ENDM
#else
#define	M      move.w   $$1*2(a0),$$3 \
               muls.w   #$$2,$$3
#endif
#if 0
;
;              M_ADD xi, Kx
;              performs: M xi, Kx, d0
;                        add.l  d0,d3
;
M_ADD          MACRO
               M        \1,\2,d0
               add.l    d0,d3
               ENDM
#else
#define	M_ADD  M        $$1,$$2,%d0 \
               add.l    %d0,%d3
#endif
#if 0
;
;                          M_SUB xi, Kx
;              performs: M xi, Kx, d0
;                        sub.l  d0,d3
;

M_SUB          MACRO
               M        \1,\2,d0
               sub.l    d0,d3
               ENDM
#else
#define	M_SUB  M        $$1,$$2,%d0 \
               sub.l    %d0,%d3 

#if 0
;              MT   ti, Kx, <dest reg>
;              performs: (t[ ti ] * (Kx))
;
MT             MACRO
               move.l   \1*4(a3),\3
               muls.w   #\2,\3
               ENDM

#else
#define	MT     move.l   %%1*4(%a3),$$3 \
               muls.w   #$$2,$$3
#endif
#if 0
;
;                          MT_ADD ti, Kx
;              performs: M ti, Kx, d0
;                        add.l  d0,d3
;
MT_ADD         MACRO
               MT       \1,\2,d0
               add.l    d0,d3
               ENDM
#else
#define	MT_ADD MT       $$1,$$2,%d0 \
               add.l    %d0,%d3
#endif
#if 0
;
;                          MT_SUB ti, Kx
;              performs: MT ti, Kx, d0
;                        sub.l  d0,d3
;
MT_SUB          MACRO
               MT       \1,\2,d0
               sub.l    d0,d3
               ENDM

#else
#define	MT_SUB MT       $$1,$$2,%d0 \
               sub.l    %d0,%d3

#endif
#if 0
;
;              IMDCT_FIX <reg>
;              performs <reg> = <reg> >> IMDCT_BITS
;
IMDCT_FIX      MACRO
               asr.l    d6,\1
               ENDM
#else
#define	IMDCT_FIX	asr.l    d6,$$1
#endif
#if 0
;              W   <reg>, wi   -> <reg> -> out[ wi ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS + prev[ wi ] -> out[ wi ]
;
W              MACRO
               muls.w   \2*2(a2),\1
               asr.l    d6,\1
               add.w    \2*2(a5),\1
               move.w   \1,\2*2*32(a1)
               ENDM
#else
#define	W      muls.w   $$2*2(%a2),%%1 \
               asr.l    %d6,$$1 \
               add.w    $$2*2(%a5),$$1 \
               move.w   $$1,$$2*2*32(%a1)
#endif
#if 0

;              WP   <reg>, wi   -> <reg> -> prev[ wi ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS -> prev[ wi-18 ]
;
WP             MACRO
               muls.w   \2*2(a2),\1
               asr.l    d6,\1
               move.w   \1,\2*2-36(a5)
               ENDM
#else
#define	WP     muls.w   $$2*2(%a2),$$1 \
               asr.l    %d6,$$1 \
               move.w   $$1,%%2*2-36(%a5) 
#endif
;
;              IMDCT for Long blocks
;
;              a0: input  x array (16-bit)
;              a1: output out     (16-bit)
;              a2: window array   (16-bit)
;              a3: prev array     (32-bit)
imdct_l:
               link     %a6,#-10*4    ; need 4+6 longs
               move.l   %a3,%a5
               lea      -4*4(%a6),%a3   ; t needs 4 longs
               lea      -6*4(%a3),%a4   ; s needs 6 longs
;               lea      imdct_sum_t,%a3
;               lea      imdct_sum_s,%a4
               moveq.l  #IMDCT_BITS,%d6

               M        4,K13,%d1
               M        13,K4,%d0
               sub.l    %d0,%d1      ; k1 = M( 4, K13 ) - M( 13, K4 )
               M        4,K4,%d2
               M        13,K13,%d0
               add.l    %d0,%d2      ; k2 = M( 4, K4 )  + M( 13, K13 )

; s[ 0 ] = -M( 1, K7 )  + k1 + M( 7, K1 )  + M( 10, K16 ) - M( 16, K10 )
               M        7,K1,%d3
               M_SUB    1,K7
               M_ADD    10,K16
               M_SUB    16,K10
               add.l    %d1,%d3
               move.l   %d3,0*4(%a4)

; s[ 1 ] = -M( 1, K4 )  - k1 + M( 7, K13 ) + M( 10, K4 )  + M( 16, K13 )
               M        7,K13,%d3
               M_SUB    1,K4
               M_ADD    10,K4
               M_ADD    16,K13
               sub.l    %d1,%d3
               move.l   %d3,1*4(a4)

; s[ 2 ] = -M( 1, K1 )  - k2 - M( 7, K7 )  - M( 10, K10 ) - M( 16, K16 )
               M        7,K7,%d3
               neg.l    %d3
               M_SUB    1,K1
               M_SUB    10,K10
               M_SUB    16,K16
               sub.l    %d2,%d3
               move.l   %d3,2*4(%a4)

; s[ 3 ] = -M( 1, K10 ) + k2 + M( 7, K16 ) - M( 10, K1 )  + M( 16, K7 )
               M        7,K16,%d3
               M_SUB    1,K10
               M_SUB    10,K1
               M_ADD    16,K7
               add.l    %d2,%d3
               move.l   %d3,3*4(%a4)

; s[ 4 ] = -M( 1, K13 ) + k2 - M( 7, K4 )  + M( 10, K13 ) - M( 16, K4 )
               M        10,K13,%d3
               M_SUB    7,K4
               M_SUB    1,K13
               M_SUB    16,K4
               add.l    %d2,%d3
               move.l   %d3,4*4(%a4)

; s[ 5 ] = -M( 1, K16 ) + k1 - M( 7, K10 ) + M( 10, K7 )  + M( 16, K1 )
               M        10,K7,%d3
               M_SUB    7,K10
               M_SUB    1,K16
               M_ADD    16,K1
               add.l    %d1,%d3
               move.l   %d3,5*4(%a4)

;              S   a, <dummy reg>, <dest reg>
               S        0,d0,%d3
               move.l   %d3,0*4(a3)
               S        2,d0,%d3
               move.l   %d3,1*4(a3)
               S        3,d0,%d3
               move.l   %d3,2*4(a3)
               S        5,d0,%d3
               move.l   %d3,3*4(a3)

               ; 0
               M        0,K9,%d3
               M_SUB    2,K11
               M_ADD    3,K5
               M_SUB    5,K3
               M_SUB    6,K15
               M_ADD    8,K17
               M_SUB    9,K0
               M_ADD    11,K2
               M_SUB    12,K14
               M_ADD    14,K12
               M_ADD    15,K6
               M_SUB    17,K8
               add.l    0*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4      ; win[ 17 ] can be negated to suppress this line
               W        %d3,0
               W        d4,17
               ; 1
               MT       0,K10,%d3
               MT_SUB   1,K16
               MT_ADD   2,K1
               MT_SUB   3,K7
               add.l    1*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,1
               W        d4,16
               ; 2
               M        0,K11,%d3
               M_ADD    2,K14
               M_ADD    3,K8
               M_ADD    5,K17
               M_ADD    6,K5
               M_SUB    8,K15
               M_ADD    9,K2
               M_SUB    11,K12
               M_ADD    12,K0
               M_SUB    14,K9
               M_ADD    15,K3
               M_SUB    17,K6
               add.l    2*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,2
               W        d4,15
               ; 3
               M        0,K12,%d3
               M_ADD    2,K9
               M_ADD    3,K15
               M_ADD    5,K6
               M_SUB    6,K17
               M_ADD    8,K3
               M_SUB    9,K14
               M_ADD    11,K0
               M_SUB    12,K11
               M_ADD    14,K2
               M_SUB    15,K8
               M_ADD    17,K5
               add.l    2*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,3
               W        d4,14
               ; 4
               MT       0,K13,%d3
               MT_ADD   1,K4
               MT_SUB   2,K13
               MT_ADD   3,K4
               add.l    1*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,4
               W        d4,13
               ; 5
               M        0,K14,%d3
               M_ADD    2,K0
               M_SUB    3,K6
               M_ADD    5,K15
               M_SUB    6,K8
               M_SUB    8,K5
               M_ADD    9,K12
               M_SUB    11,K9
               M_ADD    12,K2
               M_ADD    14,K11
               M_ADD    15,K17
               M_ADD    17,K3
               add.l    0*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,5
               W        d4,12
               ; 6
               M        0,K15,%d3
               M_ADD    2,K5
               M_SUB    3,K0
               M_SUB    5,K9
               M_ADD    6,K14
               M_SUB    8,K11
               M_ADD    9,K6
               M_ADD    11,K3
               M_SUB    12,K8
               M_ADD    14,K17
               M_SUB    15,K12
               M_SUB    17,K2
               add.l    3*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,6
               W        d4,11
               ; 7
               MT       0,K16,%d3
               MT_ADD   1,K10
               MT_SUB   2,K7
               MT_SUB   3,K1
               add.l    4*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,7
               W        d4,10
               ; 8
               M        0,K17,%d3
               M_ADD    2,K15
               M_SUB    3,K14
               M_SUB    5,K12
               M_ADD    6,K11
               M_ADD    8,K9
               M_SUB    9,K8
               M_SUB    11,K6
               M_ADD    12,K5
               M_ADD    14,K3
               M_SUB    15,K2
               M_SUB    17,K0
               add.l    5*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               neg.l    d4
               W        %d3,8
               W        d4,9

               ; 9+9
               M        0,K8,%d3
               neg.l    %d3
               M_ADD    2,K6
               M_SUB    3,K12
               M_ADD    5,K14
               M_ADD    6,K2
               M_SUB    8,K0
               M_SUB    9,K17
               M_ADD    11,K15
               M_SUB    12,K3
               M_ADD    14,K5
               M_ADD    15,K11
               M_SUB    17,K9
               sub.l    3*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,18
               WP       d4,35
               ; 10+9
               MT       0,K7,%d3
               neg.l    %d3
               MT_ADD   1,K1
               MT_ADD   2,K16
               MT_SUB   3,K10
               sub.l    4*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,19
               WP       d4,34
               ; 11+9
               M        0,K6,%d3
               neg.l    %d3
               M_ADD    2,K3
               M_ADD    3,K9
               M_SUB    5,K10
               M_SUB    6,K12
               M_ADD    8,K2
               M_ADD    9,K15
               M_SUB    11,K5
               M_ADD    12,K17
               M_ADD    14,K8
               M_SUB    15,K14
               M_SUB    17,K11
               sub.l    5*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,20
               WP       d4,33
               ; 12+9
               M        0,K5,%d3
               neg.l    %d3
               M_ADD    2,K8
               M_ADD    3,K2
               M_SUB    5,K11
               M_SUB    6,K0
               M_ADD    8,K14
               M_ADD    9,K3
               M_SUB    11,K17
               M_SUB    12,K6
               M_SUB    14,K15
               M_ADD    15,K9
               M_ADD    17,K12
               add.l    5*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,21
               WP       d4,32
               ; 13+9
               MT       0,K4,%d3
               neg.l    %d3
               MT_ADD   1,K13
               MT_ADD   2,K4
               MT_ADD   3,K13
               add.l    4*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,22
               WP       d4,31
               ; 14+9
               M        0,K3,%d3
               neg.l    %d3
               M_SUB    2,K17
               M_ADD    3,K11
               M_ADD    5,K2
               M_ADD    6,K9
               M_SUB    8,K12
               M_SUB    9,K5
               M_SUB    11,K8
               M_SUB    12,K15
               M_ADD    14,K6
               M_ADD    15,K0
               M_ADD    17,K14
               add.l    3*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,23
               WP       d4,30
               ; 15+9
               M        0,K2,%d3
               neg.l    %d3
               M_SUB    2,K12
               M_SUB    3,K17
               M_ADD    5,K8
               M_ADD    6,K3
               M_ADD    8,K6
               M_ADD    9,K11
               M_SUB    11,K14
               M_SUB    12,K9
               M_SUB    14,K0
               M_SUB    15,K5
               M_SUB    17,K15
               add.l    0*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,24
               WP       d4,29
               ; 16+9
               MT       0,K1,%d3
               neg.l    %d3
               MT_SUB   1,K7
               MT_SUB   2,K10
               MT_SUB   3,K16
               add.l    1*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,25
               WP       d4,28
               ; 17+9
               M        0,K0,%d3
               neg.l    %d3
               M_SUB    2,K2
               M_SUB    3,K3
               M_SUB    5,K5
               M_SUB    6,K6
               M_SUB    8,K8
               M_SUB    9,K9
               M_SUB    11,K11
               M_SUB    12,K12
               M_SUB    14,K14
               M_SUB    15,K15
               M_SUB    17,K17
               add.l    2*4(a4),%d3
               IMDCT_FIX %d3
               move.l   %d3,d4
               WP       %d3,26
               WP       d4,27

               move.l   a5,a3
               unlk     a6

               rts

#define	K0	16244
#define	K1      15137
#define	K2      12998
#define	K3      9974
#define	K4      6270
#define	K5      2139

#if 0
;              M3   xi, Kx, <dest reg>
;              performs: ((INT32)x[ xi*3 ] * (Kx))
;
M3             MACRO
               move.w   \1*6(a0),\3
               muls.w   #\2,\3
               ENDM
#else
#endif
#if 0
;
;              M3_ADD xi, Kx
;              performs: M3 xi, Kx, d0
;                        add.l  d0,d3
;
M3_ADD         MACRO
               M3       \1,\2,d0
               add.l    d0,d3
               ENDM

#else
#endif
#if 0
;
;              M3_SUB xi, Kx
;              performs: M3 xi, Kx, d0
;                        sub.l  d0,d3
;
M3_SUB         MACRO
               M3       \1,\2,d0
               sub.l    d0,d3
               ENDM
#else
#endif
#if 0

;              W3   <reg>, wi   -> <reg> * win[ wi ] + out[ wi ] -> out[ wi ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS + out[ wi ] -> out[ wi ]
;
W3             MACRO
               muls.w   \2*2(a2),\1
               asr.l    d6,\1
               add.w    \1,\2*2(a1)
               ENDM

#else
#endif
#if 0
;              W31   <reg>, oi, wi   -> <reg> * win[ wi ] + prev[ oi ] -> out[ oi*32 ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS + prev[ oi ] -> out[ oi*32 ]
;
W31            MACRO
               muls.w   \3*2(a2),\1
               asr.l    d6,\1
               add.w    \2*2(a5),\1
               move.w    \1,\2*2*32(a1)
               ENDM
#else
#endif
#if 0

;              W32   <reg>, oi, wi   -> <reg> * win[ wi ] -> out[ oi*32 ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS -> out[ oi*32 ]
;
W32            MACRO
               muls.w   \3*2(a2),\1
               asr.l    d6,\1
               move.w   \1,\2*2*32(a1)
               ENDM
#else
#endif
#if 0

;              W33   <reg>, oi, wi   -> <reg> * win[ wi ] + out[ oi*32 ] -> out[ oi*32 ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS + out[ oi*32 ] -> out[ oi*32 ]
;
W33            MACRO
               muls.w   \3*2(a2),\1
               asr.l    d6,\1
               add.w    \1,\2*2*32(a1)
               ENDM
#else
#endif
#if 0

;              W34   <reg>, oi, wi   -> <reg> * win[ wi ] -> prev[ oi ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS -> prev[ oi ]
;
W34            MACRO
               muls.w   \3*2(a2),\1
               asr.l    d6,\1
               move.w   \1,\2*2(a5)
               ENDM
#else
#endif
#if 0

;              W35   <reg>, oi, wi   -> <reg> * win[ wi ] + prev[ oi ] -> prev[ oi ]
;              performs: (<reg> * win[ wi ]) >> WIN_BITS + prev[ oi ] -> prev[ oi ]
;
W35            MACRO
               muls.w   \3*2(a2),\1
               asr.l    d6,\1
               add.w    \1,\2*2(a5)
               ENDM
#else
#endif


;
;              IMDCT for Short blocks
;
;              a0: input  x array (16-bit)
;              a1: output out     (16-bit)
;              a2: window array   (16-bit)
;              a3: prev array     (32-bit)
imdct_s
;   move.w #$F00,$DFF180
               link     a6,#-4*4    ; need 2+2 longs
               move.l   a3,a5
               lea      -2*4(a6),a3   ; t needs 2 longs
               lea      -2*4(a3),a4   ; s needs 2 longs
;               lea      imdct_sum_t,a3
;               lea      imdct_sum_s,a4
               moveq.l  #IMDCT_BITS,d6

               ; STEP 1
               ; O( 0..5 ) = prev[ 0.. 5 ]

               move.w   0*2(a5),0*2*32(a1)
               move.w   1*2(a5),1*2*32(a1)
               move.w   2*2(a5),2*2*32(a1)
               move.w   3*2(a5),3*2*32(a1)
               move.w   4*2(a5),4*2*32(a1)
               move.w   5*2(a5),5*2*32(a1)

               ; Calc s[0..1],  t[0..1]
               ;
               M3       1,K1,d3
               M3_ADD   4,K4
               move.l   d3,0*4(a4) ; s[ 0 ] = M3( 1, K1 ) + M3( 4, K4 )
               M3       1,K4,d3
               M3_SUB   4,K1
               move.l   d3,1*4(a4) ; s[ 1 ] = M3( 1, K4 ) - M3( 4, K1 )

               move.w   0*6(a0),d3
               sub.w    3*6(a0),d3
               ext.l    d3
               move.l   d3,0*4(a3) ; t[ 0 ] =  x[0*3] - x[3*3]
               move.w   2*6(a0),d3
               add.w    5*6(a0),d3
               ext.l    d3
               move.l   d3,1*4(a3) ; t[ 1 ] =  x[2*3] + x[5*3]

               ; 0
               M3       0,K3,d3
               M3_SUB   2,K5
               M3_ADD   3,K0
               M3_SUB   5,K2
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W31      d3,6,0
               W31      d4,11,5
               ; 1
               MT       0,K4,d3
               MT_ADD   1,K1
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W31      d3,7,1
               W31      d4,10,4
               ; 2
               M3       0,K5,d3
               M3_ADD   2,K3
               M3_SUB   3,K2
               M3_SUB   5,K0
               sub.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W31      d3,8,2
               W31      d4,9,3

               ; 3+3
               M3       0,K2,d3
               neg.l    d3
               M3_ADD   2,K0
               M3_ADD   3,K5
               M3_SUB   5,K3
               add.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W32      d3,12,6
               W32      d4,17,11
               ; 4+3
               MT       0,K1,d3
               neg.l    d3
               MT_ADD   1,K4
               sub.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W32      d3,13,7
               W32      d4,16,10
               ; 5+3
               M3       0,K0,d3
               neg.l    d3
               M3_SUB   2,K2
               M3_SUB   3,K3
               M3_SUB   5,K5
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W32      d3,14,8
               W32      d4,15,9

               ; STEP 2
               addq.l   #2,a0    ; in++;

               ; Calc s[0..1],  t[0..1]
               ;
               M3       1,K1,d3
               M3_ADD   4,K4
               move.l   d3,0*4(a4) ; s[ 0 ] = M3( 1, K1 ) + M3( 4, K4 )
               M3       1,K4,d3
               M3_SUB   4,K1
               move.l   d3,1*4(a4) ; s[ 1 ] = M3( 1, K4 ) - M3( 4, K1 )

               move.w   0*6(a0),d3
               sub.w    3*6(a0),d3
               ext.l    d3
               move.l   d3,0*4(a3) ; t[ 0 ] =  x[0*3] - x[3*3]
               move.w   2*6(a0),d3
               add.w    5*6(a0),d3
               ext.l    d3
               move.l   d3,1*4(a3) ; t[ 1 ] =  x[2*3] + x[5*3]

               ; 0
               M3       0,K3,d3
               M3_SUB   2,K5
               M3_ADD   3,K0
               M3_SUB   5,K2
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W33      d3,12,0
               W33      d4,17,5
               ; 1
               MT       0,K4,d3
               MT_ADD   1,K1
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W33      d3,13,1
               W33      d4,16,4
               ; 2
               M3       0,K5,d3
               M3_ADD   2,K3
               M3_SUB   3,K2
               M3_SUB   5,K0
               sub.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W33      d3,14,2
               W33      d4,15,3

               ; 3+3
               M3       0,K2,d3
               neg.l    d3
               M3_ADD   2,K0
               M3_ADD   3,K5
               M3_SUB   5,K3
               add.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W34      d3,0,6
               W34      d4,5,11
               ; 4+3
               MT       0,K1,d3
               neg.l    d3
               MT_ADD   1,K4
               sub.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W34      d3,1,7
               W34      d4,4,10
               ; 5+3
               M3       0,K0,d3
               neg.l    d3
               M3_SUB   2,K2
               M3_SUB   3,K3
               M3_SUB   5,K5
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W34      d3,2,8
               W34      d4,3,9

               ; STEP 3
               addq.l   #2,a0    ; in++;

               ; Calc s[0..1],  t[0..1]
               ;
               M3       1,K1,d3
               M3_ADD   4,K4
               move.l   d3,0*4(a4) ; s[ 0 ] = M3( 1, K1 ) + M3( 4, K4 )
               M3       1,K4,d3
               M3_SUB   4,K1
               move.l   d3,1*4(a4) ; s[ 1 ] = M3( 1, K4 ) - M3( 4, K1 )

               move.w   0*6(a0),d3
               sub.w    3*6(a0),d3
               ext.l    d3
               move.l   d3,0*4(a3) ; t[ 0 ] =  x[0*3] - x[3*3]
               move.w   2*6(a0),d3
               add.w    5*6(a0),d3
               ext.l    d3
               move.l   d3,1*4(a3) ; t[ 1 ] =  x[2*3] + x[5*3]

               ; 0
               M3       0,K3,d3
               M3_SUB   2,K5
               M3_ADD   3,K0
               M3_SUB   5,K2
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W35      d3,0,0
               W35      d4,5,5
               ; 1
               MT       0,K4,d3
               MT_ADD   1,K1
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W35      d3,1,1
               W35      d4,4,4
               ; 2
               M3       0,K5,d3
               M3_ADD   2,K3
               M3_SUB   3,K2
               M3_SUB   5,K0
               sub.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               neg.l    d4
               W35      d3,2,2
               W35      d4,3,3

               ; 3+3
               M3       0,K2,d3
               neg.l    d3
               M3_ADD   2,K0
               M3_ADD   3,K5
               M3_SUB   5,K3
               add.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W34      d3,6,6
               W34      d4,11,11
               ; 4+3
               MT       0,K1,d3
               neg.l    d3
               MT_ADD   1,K4
               sub.l    1*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W34      d3,7,7
               W34      d4,10,10
               ; 5+3
               M3       0,K0,d3
               neg.l    d3
               M3_SUB   2,K2
               M3_SUB   3,K3
               M3_SUB   5,K5
               sub.l    0*4(a4),d3
               IMDCT_FIX d3
               move.l   d3,d4
               W34      d3,8,8
               W34      d4,9,9

               subq.l   #4,a0    ; in -=2 (restore in)
               move.l   a5,a3

               unlk     a6

               rts

imdct_win0     dc.w     715, 2139, 3546, 4927, 6270, 7565
               dc.w     8803, 9974, 11069, 12080, 12998, 13818
               dc.w     14533, 15137, 15626, 15996, 16244, 16368
               dc.w     16368, 16244, 15996, 15626, 15137, 14533
               dc.w     13818, 12998, 12080, 11069, 9974, 8803
               dc.w     7565, 6270, 4927, 3546, 2139, 715
imdct_win0_odd dc.w     715, -2139, 3546, -4927, 6270, -7565
               dc.w     8803, -9974, 11069, -12080, 12998, -13818
               dc.w     14533, -15137, 15626, -15996, 16244, -16368
               dc.w     16368, -16244, 15996, -15626, 15137, -14533
               dc.w     13818, -12998, 12080, -11069, 9974, -8803
               dc.w     7565, -6270, 4927, -3546, 2139, -715

imdct_win1     dc.w     715, 2139, 3546, 4927, 6270, 7565
               dc.w     8803, 9974, 11069, 12080, 12998, 13818
               dc.w     14533, 15137, 15626, 15996, 16244, 16368
               dc.w     16384, 16384, 16384, 16384, 16384, 16384
               dc.w     16244, 15137, 12998, 9974, 6270, 2139
               dc.w     0, 0, 0, 0, 0, 0
imdct_win1_odd dc.w     715, -2139, 3546, -4927, 6270, -7565
               dc.w     8803, -9974, 11069, -12080, 12998, -13818
               dc.w     14533, -15137, 15626, -15996, 16244, -16368
               dc.w     16384, -16384, 16384, -16384, 16384, -16384
               dc.w     16244, -15137, 12998, -9974, 6270, -2139
               dc.w     0, 0, 0, 0, 0, 0

imdct_win3     dc.w     0, 0, 0, 0, 0, 0
               dc.w     2139, 6270, 9974, 12998, 15137, 16244
               dc.w     16384, 16384, 16384, 16384, 16384, 16384
               dc.w     16368, 16244, 15996, 15626, 15137, 14533
               dc.w     13818, 12998, 12080, 11069, 9974, 8803
               dc.w     7565, 6270, 4927, 3546, 2139, 715
imdct_win3_odd dc.w     0, 0, 0, 0, 0, 0
               dc.w     2139, -6270, 9974, -12998, 15137, -16244
               dc.w     16384, -16384, 16384, -16384, 16384, -16384
               dc.w     16368, -16244, 15996, -15626, 15137, -14533
               dc.w     13818, -12998, 12080, -11069, 9974, -8803
               dc.w     7565, -6270, 4927, -3546, 2139, -715

imdct_win2     dc.w     2139, 6270, 9974, 12998, 15137, 16244
               dc.w     16244, 15137, 12998, 9974, 6270, 2139
imdct_win2_odd dc.w     2139, -6270, 9974, -12998, 15137, -16244
               dc.w     16244, -15137, 12998, -9974, 6270, -2139

imdct_win      dc.l     imdct_win0
               dc.l     imdct_win1
               dc.l     imdct_win2
               dc.l     imdct_win3

imdct_win_odd  dc.l     imdct_win0_odd
               dc.l     imdct_win1_odd
               dc.l     imdct_win2_odd
               dc.l     imdct_win3_odd

