/*------------------------------------------------------------------------------

    File    :   MPEGSUB.C

    Author  :   Stéphane TAVENARD

    (C) Copyright 1997-1998 Stéphane TAVENARD
        All Rights Reserved

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |20/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |27/04/1997| Added MPEGSUB_init                                   ST
    3   |18/05/1997| Optimized Subband synthesis                          ST
    4   |27/05/1997| Removed IMDCT -> now MPEGIMDCT module                ST
    5   |05/06/1997| Added FPU Optimized version                          ST
    6   |01/11/1997| Use non static vars of asm optimized funcs           ST
    7   |21/06/1998| Added MPEGSUB_scale                                  ST

    ------------------------------------------------------------------------

    MPEG Audio Common layers Sub routines

------------------------------------------------------------------------------*/


#include "defs.h"
#include "mpegaud.h"
#include "mpegsub.h"
#include "mpegtab.h"
#include <assert.h>
#include <math.h>

#ifdef MPEGAUD_INT
#define SUB_INT
#define IMDCT_INT
#endif

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM_2)
#ifdef MPEGAUD_INT
#include "mpegsubb.h"
#else
#include "mpegsubf.h" // #5
#endif
#endif


#define DETECT_CLIP

#ifndef PI
#define PI 3.14159265358979323846
#endif

#ifdef SUB_INT

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM_2)
#define SUB_TYPE INT16
#else
#define SUB_TYPE MPEGAUD_FRACT_TYPE
#endif

#define SUB_DCT_TYPE INT32

#define SUB_BAND_BITS MPEGAUD_FRACT_BITS
#define SUB_DEW_BITS MPEGTAB_DEW_BITS
#define SH 1
#define SUB_COS_BITS (16-SH)
#define SUB_OUT_BITS 16
#define SUB_IMDCT_BITS 14

// Align to BAND_BITS bit the result
#define MULT_COS( a, b ) (((a) * (b))>>(SUB_COS_BITS))
// Align to 16 bit the result
#define MULT_DEW( a, b ) ((a) * (b))
//#define SCALE_DEW( s ) ((s)>>(SUB_DEW_BITS+SUB_BAND_BITS-16+SUB_OUT_BITS-15)) // #7 Removed
#define SCALE_DEW( s ) ((s)>>(dew_shift)) // #7 Scaled dewindow
#define MULT_IMDCT( a, b ) (((a) * (b))>>(SUB_IMDCT_BITS))
#else

#define SUB_TYPE REAL
#define SUB_DCT_TYPE REAL
#define SUB_DEW_BITS 0
#define SUB_COS_BITS 0
#define SUB_IMDCT_BITS 0
#define MULT_COS( a, b ) ((a) * (b))
#define MULT_DEW( a, b ) ((a) * (b))
//#define SCALE_DEW( s ) ((s) * (REAL)MPA_SCALE) // #7 Removed
#define SCALE_DEW( s ) (s) // #7 Scaled dewindow
#define MULT_IMDCT( a, b ) ((a) * (b))

#endif

#ifndef SUB_INT
// cosi_j is the result of: 1 / ( 2 * cos( i * PI / j ) )
#define cos1_64  (REAL)0.50060299823520
#define cos3_64  (REAL)0.50547095989754
#define cos5_64  (REAL).51544730992262
#define cos7_64  (REAL)0.53104259108978
#define cos9_64  (REAL)0.55310389603444
#define cos11_64 (REAL)0.58293496820613
#define cos13_64 (REAL)0.62250412303566
#define cos15_64 (REAL)0.67480834145501
#define cos17_64 (REAL)0.74453627100230
#define cos19_64 (REAL)0.83934964541553
#define cos21_64 (REAL)0.97256823786196
#define cos23_64 (REAL)1.16943993343288
#define cos25_64 (REAL)1.48416461631417
#define cos27_64 (REAL)2.05778100995341
#define cos29_64 (REAL)3.40760841846872
#define cos31_64 (REAL)10.1900081235480
#define cos1_32  (REAL)0.50241928618816
#define cos3_32  (REAL)0.52249861493969
#define cos5_32  (REAL)0.56694403481636
#define cos7_32  (REAL)0.64682178335999
#define cos9_32  (REAL)0.78815462345125
#define cos11_32 (REAL)1.06067768599035
#define cos13_32 (REAL)1.72244709823833
#define cos15_32 (REAL)5.10114861868917
#define cos1_16  (REAL)0.50979557910416
#define cos3_16  (REAL)0.60134488693505
#define cos5_16  (REAL)0.89997622313642
#define cos7_16  (REAL)2.56291544774151
#define cos1_8   (REAL)0.54119610014620
#define cos3_8   (REAL)1.30656296487638
#define cos1_4   (REAL)0.70710678118655
#else
// Fixed point version with 16-bit decimals
#define cos1_64  (32808>>SH)
#define cos3_64  (33127>>SH)
#define cos5_64  (33780>>SH)
#define cos7_64  (34802>>SH)
#define cos9_64  (36248>>SH)
#define cos11_64 (38203>>SH)
#define cos13_64 (40796>>SH)
#define cos15_64 (44224>>SH)
#define cos17_64 (48794>>SH)
#define cos19_64 (55008>>SH)
#define cos21_64 (63738>>SH)
#define cos23_64 (76640>>SH)
#define cos25_64 (97266>>SH)
#define cos27_64 (134859>>SH)
#define cos29_64 (223321>>SH)
#define cos31_64 (667812>>SH)
#define cos1_32  (32927>>SH)
#define cos3_32  (34242>>SH)
#define cos5_32  (37155>>SH)
#define cos7_32  (42390>>SH)
#define cos9_32  (51653>>SH)
#define cos11_32 (69513>>SH)
#define cos13_32 (112882>>SH)
#define cos15_32 (334309>>SH)
#define cos1_16  (33410>>SH)
#define cos3_16  (39410>>SH)
#define cos5_16  (58981>>SH)
#define cos7_16  (167963>>SH)
#define cos1_8   (35468>>SH)
#define cos3_8   (85627>>SH)
#define cos1_4   (46341>>SH)
#endif

#if !defined(ASM_OPTIMIZE) && !defined(COLDFIRE_ASM_2)

static void sub_dct( SUB_DCT_TYPE *p )
{
  SUB_DCT_TYPE pp[ 16 ];
  register SUB_DCT_TYPE *d1, *d2, *s1, *s2;

  d1 = &pp[ 0 ]; d2 = &pp[ 8 ]; s1 = &p[ 0 ]; s2 = &p[ 16 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_32,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_32,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos5_32,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos7_32,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos9_32,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos11_32, *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos13_32, *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos15_32, *s1++ - *s2 );

  d1 = &p[ 0 ]; d2 = &p[ 4 ];  s1 = &pp[ 0 ]; s2 = &pp[ 8 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos5_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos7_16,  *s1++ - *s2 );
  d1 = &p[ 8 ]; d2 = &p[ 12 ]; s1 = &pp[ 8 ]; s2 = &pp[ 16 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos5_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos7_16,  *s1++ - *s2 );

  d1 = &pp[ 0 ]; d2 = &pp[ 2 ]; s1 = &p[ 0 ]; s2 = &p[ 4 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_8,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_8,  *s1++ - *s2 );
  d1 = &pp[ 4 ]; d2 = &pp[ 6 ]; s1 = &p[ 4 ]; s2 = &p[ 8 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_8,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_8,  *s1++ - *s2 );
  d1 = &pp[ 8 ]; d2 = &pp[ 10 ]; s1 = &p[ 8 ]; s2 = &p[ 12 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_8,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_8,  *s1++ - *s2 );
  d1 = &pp[ 12 ]; d2 = &pp[ 14 ]; s1 = &p[ 12 ]; s2 = &p[ 16 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_8,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_8,  *s1++ - *s2 );

  d1 = &p[ 0 ];
  *d1++ = pp[ 0 ] + pp[ 1 ]; *d1++ = MULT_COS( cos1_4, pp[ 0 ] - pp[ 1 ] );
  *d1++ = pp[ 2 ] + pp[ 3 ]; *d1++ = MULT_COS( cos1_4, pp[ 2 ] - pp[ 3 ] );
  *d1++ = pp[ 4 ] + pp[ 5 ]; *d1++ = MULT_COS( cos1_4, pp[ 4 ] - pp[ 5 ] );
  *d1++ = pp[ 6 ] + pp[ 7 ]; *d1++ = MULT_COS( cos1_4, pp[ 6 ] - pp[ 7 ] );
  *d1++ = pp[ 8 ] + pp[ 9 ]; *d1++ = MULT_COS( cos1_4, pp[ 8 ] - pp[ 9 ] );
  *d1++ = pp[ 10 ] + pp[ 11 ]; *d1++ = MULT_COS( cos1_4, pp[ 10 ] - pp[ 11 ] );
  *d1++ = pp[ 12 ] + pp[ 13 ]; *d1++ = MULT_COS( cos1_4, pp[ 12 ] - pp[ 13 ] );
  *d1++ = pp[ 14 ] + pp[ 15 ]; *d1++ = MULT_COS( cos1_4, pp[ 14 ] - pp[ 15 ] );
}

static void sub_half_dct( SUB_DCT_TYPE *p )
/*-----------------------------------------
*/
{
  SUB_DCT_TYPE pp[ 8 ];
  register SUB_DCT_TYPE *d1, *d2, *s1, *s2;
  register SUB_DCT_TYPE p1, p2;

  d1 = &pp[ 0 ]; d2 = &pp[ 4 ];  s1 = &p[ 0 ]; s2 = &p[ 8 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos5_16,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos7_16,  *s1++ - *s2 );

  d1 = &p[ 0 ]; d2 = &p[ 2 ]; s1 = &pp[ 0 ]; s2 = &pp[ 4 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_8,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_8,  *s1++ - *s2 );
  d1 = &p[ 4 ]; d2 = &p[ 6 ]; s1 = &pp[ 4 ]; s2 = &pp[ 8 ];
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos1_8,  *s1++ - *s2 );
  *d1++ = *s1 + *--s2; *d2++ = MULT_COS( cos3_8,  *s1++ - *s2 );

  d1 = &p[ 0 ];
  p1 = *d1; p2 = p[ 1 ]; *d1++ = p1 + p2; p1 -= p2; *d1++ = MULT_COS( cos1_4, p1 );
  p1 = *d1; p2 = p[ 3 ]; *d1++ = p1 + p2; p1 -= p2; *d1++ = MULT_COS( cos1_4, p1 );
  p1 = *d1; p2 = p[ 7 ]; *d1++ = p1 + p2; p1 -= p2; *d1++ = MULT_COS( cos1_4, p1 );
  p1 = *d1; p2 = p[ 9 ]; *d1++ = p1 + p2; p1 -= p2; *d1 = MULT_COS( cos1_4, p1 );

}

static void fast_dct( SUB_TYPE *samples, SUB_TYPE *sy0, SUB_TYPE *sy1, INT16 freq_div )
{
   register SUB_TYPE *x1, *x2;
   register SUB_DCT_TYPE *d;
   register SUB_DCT_TYPE s, s0, s1, s2, s3, tmp;
   SUB_DCT_TYPE p[ 16 ];
#define S0( i ) sy0[ i*16 ]
#define S1( i ) sy1[ i*16 ]
   static int init = 0;
   static FILE *fsamp;
   static FILE *fsamp_in;
   int i;

#if 0
   if (init == 0) {
    fsamp = fopen("fsamp.out", "w");
    fsamp_in = fopen("fsamp.in", "w");
    init = 1;
   }
#endif
   x1 = samples;
   x2 = samples + 31;
   d = p;
   if( freq_div == 4 ) {
      *d++ = *x1++; *d++ = *x1++; *d++ = *x1++; *d++ = *x1++;
      *d++ = *x1++; *d++ = *x1++; *d++ = *x1++; *d = *x1;
      sub_half_dct( p );
                             S0( 0 )  = p[ 1 ];  S1( 0 )  = -p[ 1 ];
      s = p[ 5 ] + p[ 7 ];   S0( 4 )  = s;       S0( 28 ) = -s;
                             S0( 8 )  = p[ 3 ];  S0( 24 ) = -p[ 3 ];
                             S0( 12 ) = p[ 7 ];  S0( 20 ) = -p[ 7 ];
                             S0( 16 ) = (SUB_DCT_TYPE)0;

      s = p[ 6 ] + p[ 7 ];
                             S1( 4 )  = S1( 28 ) = -(p[ 5 ] + s);
                             S1( 8 )  = S1( 24 ) = -(p[ 2 ] + p[ 3 ]);
                             S1( 12 ) = S1( 20 ) = -(p[ 4 ] + s);
                             S1( 16 ) = -p[ 0 ];
          return;
   }
   else if( freq_div == 2 ) {
      *d++ = *x1++; *d++ = *x1++; *d++ = *x1++; *d++ = *x1++;
      *d++ = *x1++; *d++ = *x1++; *d++ = *x1++; *d++ = *x1++;
      *d++ = *x1++; *d++ = *x1++; *d++ = *x1++; *d++ = *x1++;
      *d++ = *x1++; *d++ = *x1++; *d++ = *x1++; *d = *x1;
   }
   else { // freq_div = 1
      *d++ = *x1++ + *x2;   *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2;
      *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2;
      *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2;
      *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2; *d++ = *x1++ + *--x2; *d   = *x1   + *--x2;
   }

   sub_dct( p );

   // 5 ADD
   s0 = p[ 13 ] + p[ 15 ];
                          S0( 0 )  = p[ 1 ];  S1( 0 )  = -p[ 1 ];
   s = p[ 9 ] + s0;       S0( 2 )  = s;       S0( 30 ) = -s;
   s = p[ 5 ] + p[ 7 ];   S0( 4 )  = s;       S0( 28 ) = -s;
   s = p[ 11 ] + s0;      S0( 6 )  = s;       S0( 26 ) = -s;
                          S0( 8 )  = p[ 3 ];  S0( 24 ) = -p[ 3 ];
   s = p[ 11 ] + p[ 15 ]; S0( 10 ) = s;       S0( 22 ) = -s;
                          S0( 12 ) = p[ 7 ];  S0( 20 ) = -p[ 7 ];
                          S0( 14 ) = p[ 15 ]; S0( 18 ) = -p[ 15 ];
                          S0( 16 ) = (SUB_DCT_TYPE)0;

// 12 ADD
   s0 += p[ 14 ]; // s0 = p13 + p14 + p15
   s1 = p[ 12 ] + p[ 14 ] + p[ 15 ];
   s2 = p[ 10 ] + p[ 11 ];
   s3 = p[ 6 ] + p[ 7 ];
                          S1( 2 )  = S1( 30 ) = -(p[ 9 ] + s0);
                          S1( 4 )  = S1( 28 ) = -(p[ 5 ] + s3);
                          S1( 6 )  = S1( 26 ) = -(s0 + s2);
                          S1( 8 )  = S1( 24 ) = -(p[ 2 ] + p[ 3 ]);
                          S1( 10 ) = S1( 22 ) = -(s1 + s2);
                          S1( 12 ) = S1( 20 ) = -(p[ 4 ] + s3);
                          S1( 14 ) = S1( 18 ) = -(p[ 8 ] + s1);
                          S1( 16 ) = -p[ 0 ];

   if( freq_div > 1 ) return;

   x1 = samples;
   x2 = samples + 31;
   d = p;
   *d++ = MULT_COS( cos1_64, (*x1++ - *x2)  );
   *d++ = MULT_COS( cos3_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos5_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos7_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos9_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos11_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos13_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos15_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos17_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos19_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos21_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos23_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos25_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos27_64, (*x1++ - *--x2) );
   *d++ = MULT_COS( cos29_64, (*x1++ - *--x2) );
   *d   = MULT_COS( cos31_64, (*x1   - *--x2) );

   sub_dct( p );

// 12 ADD
   s0 = p[ 13 ] + p[ 15 ];
   s1 = p[ 11 ] + p[ 15 ];
   s2 = p[ 5 ] + p[ 7 ];
   tmp = p[ 9 ] + s0;
   s = p[ 1 ] + tmp;      S0( 1 )  = s;       S0( 31 ) = -s;
   s = s2 + tmp;          S0( 3 )  = s;       S0( 29 ) = -s;
   tmp = p[ 11 ] + s0;
   s = s2 + tmp;          S0( 5 )  = s;       S0( 27 ) = -s;
   s = p[ 3 ] + tmp;      S0( 7 )  = s;       S0( 25 ) = -s;
   s = p[ 3 ] + s1;       S0( 9 )  = s;       S0( 23 ) = -s;
   s = p[ 7 ] + s1;       S0( 11 ) = s;       S0( 21 ) = -s;
   s = p[ 7 ] + p[ 15 ];  S0( 13 ) = s;       S0( 19 ) = -s;
                          S0( 15 ) = p[ 15 ]; S0( 17 ) = -p[ 15 ];

// 21 ADD
   s0 += p[ 14 ]; // s0 = p13 + p14 + p15
   s1 = p[ 12 ] + p[ 14 ] + p[ 15 ];
   s2 = p[ 10 ] + p[ 11 ];
   s3 = p[ 6 ] + p[ 7 ];
                          S1( 1 )  = S1( 31 ) = -(p[ 1 ] + p[ 9 ] + s0);
   tmp = p[ 5 ] + s3 + s0;
                          S1( 3 )  = S1( 29 ) = -(tmp + p[ 9 ]);
                          S1( 5 )  = S1( 27 ) = -(tmp + s2);
   tmp = p[ 2 ] + p[ 3 ] + s2;
                          S1( 7 )  = S1( 25 ) = -(tmp + s0);
                          S1( 9 )  = S1( 23 ) = -(tmp + s1);
   tmp = p[ 4 ] + s3 + s1;
                          S1( 11 ) = S1( 21 ) = -(tmp + s2);
                          S1( 13 ) = S1( 19 ) = -(tmp + p[ 8 ]);
                          S1( 15 ) = S1( 17 ) = -(p[ 0 ] + p[ 8 ] + s1);

#if 0
   x1 = samples;
   for (i = 0; i < 32; i++) {
     fprintf(fsamp, "samples0,1: %08x %08x\n", S0( i ), S1( i ));
     fprintf(fsamp_in, "samples_in: %08x\n", *x1++);
   }
#endif
#undef S
}

#endif

INT16 MPEGSUB_synthesis( MPEGSUB *mpegsub,
                         MPEGAUD_FRACT_TYPE *bandPtr,
                         INT16 channel, INT16 *samples )
/*------------------------------------------------------------------
   SubBand synthesis filter
   -> Return # of pcm samples calculated
*/
{
   SUB_TYPE           *buf0, *buf1;
   SUB_TYPE           *buf_ptr;
   INT16               b_offset = mpegsub->b_offset[ channel ];
   MPEGAUD_FRACT_TYPE *bb = &mpegsub->bb[ channel ][ 0 ];

   if( b_offset & 1 ) { // Odd
      buf0 = &bb[ MPA_HANNING_SIZE + b_offset ];
      buf1 = &bb[ b_offset ];
      buf_ptr = &bb[ MPA_HANNING_SIZE ];
   }
   else { // Even
      buf0 = &bb[ b_offset ];
      buf1 = &bb[ MPA_HANNING_SIZE + b_offset ];
      buf_ptr = &bb[ 0 ];
   }

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM_2)
#ifdef MPEGAUD_INT
//   MPEGSUBB_filter_band( bandPtr, buf0, buf1 );
   MPEGSUBB_filter_band( bandPtr, buf0, buf1, mpegsub->freq_div ); // #6
#else
//   MPEGSUBF_filter_band( bandPtr, buf0, buf1 );
   MPEGSUBF_filter_band( bandPtr, buf0, buf1, mpegsub->freq_div ); // #6
#endif
#else
   fast_dct( bandPtr, buf0, buf1, mpegsub->freq_div );
#endif

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM_2)
#ifdef MPEGAUD_INT
//   MPEGSUBB_window_band( buf_ptr, samples, b_offset );
   MPEGSUBB_window_band( buf_ptr, samples, mpegsub->scaled_dewindow /* #7 */, b_offset,
                         mpegsub->w_begin, mpegsub->w_width, mpegsub->freq_div,
                         mpegsub->scaled_shift /* #7 */ ); // #6
#else
//   MPEGSUBF_window_band( buf_ptr, samples, b_offset );
   MPEGSUBF_window_band( buf_ptr, samples, mpegsub->scaled_dewindow /* #7 */, b_offset,
                         mpegsub->w_begin, mpegsub->w_width, mpegsub->freq_div ); // #6
#endif
#else
   {
      INT16 start, top, cnt0, cnt1, off0, off1, offd;
      INT16 *samp;
      register SUB_DCT_TYPE sum;
      register const SUB_TYPE *dewindow;
      register INT16 j;
// #7 Begin
#ifdef MPEGAUD_INT
      INT32 dew_shift = mpegsub->scaled_shift + SUB_BAND_BITS - 16 + SUB_OUT_BITS - 15;
#endif
// #7 End

      samp = samples;

      start = (mpegsub->w_begin + b_offset) & 15;
      top = start + mpegsub->w_width;
      if( top > 16 ) top = 16;
      cnt1 = top - start;    // From start to ...
      cnt0 = mpegsub->w_width - cnt1; // From 0 to ...
      off1 = mpegsub->freq_div*16 - cnt1;
      off0 = mpegsub->freq_div*16 - cnt0;
      offd = mpegsub->freq_div*16 - mpegsub->w_width;
      buf1 = &buf_ptr[ start ];
      buf0 = &buf_ptr[ 0 ];
//      dewindow = &MPT_dewindow[ mpegsub->w_begin ]; // #7 Removed
      dewindow = &(mpegsub->scaled_dewindow[ mpegsub->w_begin ]); // #7 Scaled dewindow
      j = mpegsub->pcm_count;

      // #3 Begin: NEW_WIN

#define MULTS sum = MULT_DEW( *dewindow++, *buf1++ )
#define MULT0 sum += MULT_DEW( *dewindow++, *buf1++ )
#define MULT1 sum += MULT_DEW( *dewindow++, *buf0++ )

#ifdef DETECT_CLIP
#define STORE buf1 += off1; buf0 += off0; dewindow += offd;\
              sum = SCALE_DEW( sum );\
              if( sum > (SUB_TYPE)32767 ) sum = (SUB_TYPE)32767;\
              else if( sum < (SUB_TYPE)-32768 ) sum = (SUB_TYPE)-32768;\
              *samp++ = (INT16)sum;
#else
#define STORE buf1 += off1; buf0 += off0; dewindow += offd;\
              sum = SCALE_DEW( sum );\
              *samp++ = (INT16)sum;
#endif

      if( mpegsub->w_width <= 4 ) {
         switch( cnt0 ) {
            case 0:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0;
                  STORE;
               }
               break;
            case 1:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT1;
                  STORE;
               }
               break;
            case 2:
               while( j-- ) {
                  MULTS; MULT0; MULT1; MULT1;
                  STORE;
               }
               break;
            case 3:
               while( j-- ) {
                  MULTS; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
         }
      }
      else if( mpegsub->w_width <= 8 ) {
         switch( cnt0 ) {
            case 0:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  STORE;
               }
               break;
            case 1:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT1;
                  STORE;
               }
               break;
            case 2:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT1; MULT1;
                  STORE;
               }
               break;
            case 3:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 4:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 5:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 6:
               while( j-- ) {
                  MULTS; MULT0; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 7:
               while( j-- ) {
                  MULTS; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
         }
      }
      else {
         switch( cnt0 ) {
            case 0:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  STORE;
               }
               break;
            case 1:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT1;
                  STORE;
               }
               break;
            case 2:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT1; MULT1;
                  STORE;
               }
               break;
            case 3:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT0; MULT0; MULT0; MULT0; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 4:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT0; MULT0; MULT0; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 5:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT0; MULT0; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 6:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT0; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 7:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT0; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 8:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 9:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT0; MULT1;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 10:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT0; MULT1; MULT1;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 11:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT0; MULT1; MULT1; MULT1;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 12:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT0; MULT1; MULT1; MULT1; MULT1;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 13:
               while( j-- ) {
                  MULTS; MULT0; MULT0; MULT1; MULT1; MULT1; MULT1; MULT1;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 14:
               while( j-- ) {
                  MULTS; MULT0; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
            case 15:
               while( j-- ) {
                  MULTS; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1; MULT1;
                  STORE;
               }
               break;
         }
      }
      // #3 End

   }
#endif // ASM_OPTIMIZE
     mpegsub->b_offset[ channel ] = (b_offset - 1) & 15;

   return mpegsub->pcm_count;
}

int MPEGSUB_reset( MPEGSUB *mpegsub )
/*-----------------------------------
   Reset the MPEGSUB module
*/
{
   INT16 ch;

   if( !mpegsub ) return -1;
   // Reset sub band buffer
   memset( mpegsub->bb, 0, MPA_MAX_CHANNELS * 2 * MPA_HANNING_SIZE * sizeof( MPEGAUD_FRACT_TYPE ) );
   // Reset offsets
   for( ch=0; ch<MPA_MAX_CHANNELS; ch++ ) {
      mpegsub->b_offset[ ch ] = 0;
   }

   return 0;

} /* MPEGSUB_reset */

// #7 Begin
int MPEGSUB_scale( MPEGSUB *mpegsub, INT32 scale_percent ) {
/*--------------------------------------------------------
   Set the scale of the output of synthesis filter
   input: scale_percent = scale in % (100 is nominal value)
   return 0 if Ok
*/
   INT16 i;

   if( mpegsub->scale_percent == scale_percent ) return 0;

   if( scale_percent <= 0 ) return -1;
   if( scale_percent > 10000 ) return -2;

#ifdef MPEGAUD_INT
   {
      INT32 s, c;

      s = MPEGTAB_DEW_BITS;
      c = scale_percent;
      while( (c <= 50) && (s < 17) ) {
         c <<= 1;
         s++;
      }
      while( (c > 100) && (s > 2) ) {
         c >>= 1;
         s--;
      }
      if( s == 2 ) c = 100; // Limit max scale
      mpegsub->scaled_shift = s;
      c <<= 14;
      c /= 100;
      for( i=0; i<MPA_HANNING_SIZE; i++ ) {
         mpegsub->scaled_dewindow[ i ] = (MPEGTAB_DEW_TYPE)(((INT32)MPT_dewindow[ i ] * c)>>14);
      }
   }
#else
   {
      REAL coeff;

      coeff = (REAL)(scale_percent) * (MPA_SCALE * 0.01);
      for( i=0; i<MPA_HANNING_SIZE; i++ ) {
         mpegsub->scaled_dewindow[ i ] = MPT_dewindow[ i ] * coeff;
      }
   }
#endif
   mpegsub->scale_percent = scale_percent;
   return 0;
}
// #7 End

void MPEGSUB_close( MPEGSUB *mpegsub )
/*------------------------------------
   Close the MPEGSUB module
*/
{
   if( !mpegsub ) return;
   free( mpegsub );

} /* MPEGSUB_close */

MPEGSUB *MPEGSUB_open( INT16 freq_div, INT16 quality )
/*----------------------------------------------------
   Open the MPEGSUB module
*/
{
   MPEGSUB *mpegsub;

   mpegsub = (MPEGSUB *)malloc( sizeof(MPEGSUB) );
   if( !mpegsub ) return NULL;
   (void)MPEGSUB_reset( mpegsub );
   mpegsub->scale_percent = 0; // #7
   MPEGSUB_scale( mpegsub, 100 ); // #7

   switch( freq_div ) {
      case 2:  mpegsub->pcm_count = MPA_SBLIMIT>>1; break;
      case 4:  mpegsub->pcm_count = MPA_SBLIMIT>>2; break;
      default: mpegsub->pcm_count = MPA_SBLIMIT; freq_div = 1; break;
   }
   switch( quality ) {
      case 0:  mpegsub->w_begin = 6; mpegsub->w_width = 4; break;
      case 1:  mpegsub->w_begin = 4; mpegsub->w_width = 8; break;
      default: mpegsub->w_begin = 0; mpegsub->w_width = 16; quality = 2; break;
   }

   mpegsub->freq_div = freq_div;
   mpegsub->quality = quality;

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM_2)
#ifdef MPEGAUD_INT
//   MPEGSUBB_config( freq_div, quality, 0 ); #6
#else
//   MPEGSUBF_config( freq_div, quality, 0 ); #6
#endif
#endif

   return mpegsub;

} /* MPEGSUB_open */


