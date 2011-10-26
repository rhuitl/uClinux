/*-----------------------------------------------------------------------------

    File    :   MPEGIMDC.C

    Author  :   Stéphane TAVENARD

    (C) Copyright 1997-1999 Stéphane TAVENARD
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
    0   |27/05/1997| Initial revision                                     ST
    1   |05/06/1997| Added FPU Optimized version                          ST
    2   |02/05/1998| PPC Support                                          ST
    3   |24/05/1999| Added some const                                     ST
    4   |21/10/1999| Added imdct table generation/usage                   RS

    ------------------------------------------------------------------------

    MPEG Audio IMDCT hybrid filter

-----------------------------------------------------------------------------*/


#include "defs.h"
#include "mpegaud.h"
#include "mpegimdc.h"
#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM)
#ifdef MPEGAUD_INT
#include "mpegimda.h"
#else
#include "mpegimdf.h" // #1
#endif
#endif
#include <math.h>

#ifdef MPEGAUD_INT
#define IMDCT_INT
#ifdef USE_IMDCT_TABLE
#include "imdct.h"
#endif
#else
#define NEW_IMDCT // This one is faster for float (but not accurate for int math)
#endif

#ifdef IMDCT_TABLE_GEN
#include <stdlib.h>
#endif

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM)

int MPEGIMDCT_hybrid( MPEGIMDCT *mpegimdct, MPEGAUD_FRACT_TYPE *in,
                      MPEGAUD_FRACT_TYPE *out, INT16 block_type, BOOL mixed,
                      INT16 ch, INT16 sb_max )
/*--------------------------------------------------------------------------
   Apply the hybrid imdct to a granule
   Return 0 if Ok
*/
{
#ifdef MPEGAUD_INT
   MPEGIMDA_hybrid( in, out, mpegimdct->prevblk[ ch ], block_type, mixed, sb_max );
#else
   MPEGIMDF_hybrid( in, out, mpegimdct->prevblk[ ch ], block_type, mixed, sb_max );
#endif

MPEGAUD_CHECK_DEMO;

   return 0;

} /* MPEGIMDCT_hybrid */


#else // -> NOT ASM_OPTIMIZE


#ifdef NEW_IMDCT

#define SBLIMIT MPA_SBLIMIT
#define SSLIMIT MPA_SSLIMIT

#ifndef M_PI // #2
#define M_PI 3.14159265358979
#endif

#ifdef IMDCT_INT

#define WIN_BITS 14 // 14
#define TFC_BITS 14 // 14
#define COS_BITS 14 // 14

#define WIN_MULT( val, windex ) ( ((val) * w[ windex ]) >> WIN_BITS )
#define T36_MULT( val, tindex ) ( ((val) * tfcos36[ tindex ]) >> TFC_BITS )
#define T12_MULT( val, tindex ) ( ((val) * tfcos12[ tindex ]) >> TFC_BITS )
#define COS_MULT( val, cosval ) ( ((val) * (cosval)) >> COS_BITS )

#define CM( val, cindex ) ( (val) * c[ cindex ] ) )
#define CM1( val ) ( (val) << COS_BITS )
#define CF( val ) ( (val) >> (COS_BITS+SH_BITS) )

#define IMDCT_TYPE INT32
#define WIN_TYPE INT32
#define COS_TYPE INT16

#else

#define WIN_MULT( val, windex ) ( (val) * w[ windex ] )
#define T36_MULT( val, tindex ) ( (val) * tfcos36[ tindex ] )
#define T12_MULT( val, tindex ) ( (val) * tfcos12[ tindex ] )
#define COS_MULT( val, cosval ) ( (val) * (cosval) )
#define CM( val, cindex ) ( (val) * c[ cindex ] )
#define CM1( val ) ( val )
#define CF( val ) ( val )

#define IMDCT_TYPE REAL
#define WIN_TYPE REAL
#define COS_TYPE REAL

#endif

static COS_TYPE COS1[12][6];
static WIN_TYPE win[4][36];
static WIN_TYPE win1[4][36];
static COS_TYPE COS9[9];
static COS_TYPE COS6_1, COS6_2;
static IMDCT_TYPE tfcos36[9];
static IMDCT_TYPE tfcos12[3];


static void dct36( MPEGAUD_FRACT_TYPE *inbuf, MPEGIMDCT_BLOCK_TYPE *prev,
                   WIN_TYPE *wintab, MPEGAUD_FRACT_TYPE *tsbuf )
{
  register MPEGAUD_FRACT_TYPE *in = inbuf;
#define I0( i ) in[2*(i)+0]
#define I1( i ) in[2*(i)+1]
  in[17]+=in[16]; in[16]+=in[15]; in[15]+=in[14];
  in[14]+=in[13]; in[13]+=in[12]; in[12]+=in[11];
  in[11]+=in[10]; in[10]+=in[9];  in[9] +=in[8];
  in[8] +=in[7];  in[7] +=in[6];  in[6] +=in[5];
  in[5] +=in[4];  in[4] +=in[3];  in[3] +=in[2];
  in[2] +=in[1];  in[1] +=in[0];

  in[17]+=in[15]; in[15]+=in[13]; in[13]+=in[11]; in[11]+=in[9];
  in[9] +=in[7];  in[7] +=in[5];  in[5] +=in[3];  in[3] +=in[1];
  {

#define MACRO0(v) { \
    IMDCT_TYPE tmp = sum0 + sum1; \
    sum0 -= sum1; \
    ts[SBLIMIT*(8-(v))] = prev[8-(v)] + WIN_MULT( sum0, 8-(v) ); \
    prev[8-(v)] = WIN_MULT( tmp, 26-(v) ); \
    ts[SBLIMIT*(9+(v))] = prev[9+(v)] + WIN_MULT( sum0, 9+(v) ); \
    prev[9+(v)] = WIN_MULT( tmp, 27+(v) ); }
#define MACRO1(v) { \
    IMDCT_TYPE sum0, sum1; \
    sum0 = tmp1a + tmp2a; \
    sum1 = T36_MULT( tmp1b + tmp2b, v ); \
    MACRO0(v); }
#define MACRO2(v) { \
    IMDCT_TYPE sum0, sum1; \
    sum0 = tmp2a - tmp1a; \
    sum1 = T36_MULT( tmp2b - tmp1b, v ); \
    MACRO0(v); }

    register const COS_TYPE *c = COS9;
    register WIN_TYPE *w = wintab;
    register MPEGAUD_FRACT_TYPE *ts = tsbuf;

    IMDCT_TYPE ta33,ta66,tb33,tb66;

    ta33 = CM( I0(3), 3 );
    ta66 = CM( I0(6), 6 );
    tb33 = CM( I1(3), 3 );
    tb66 = CM( I1(6), 6 );

    {
      IMDCT_TYPE tmp1a,tmp2a,tmp1b,tmp2b;

      tmp1a = CF( CM( I0(1), 1 ) + ta33 + CM( I0(5), 5 ) + CM( I0(7), 7 ) );
      tmp1b = CF( CM( I1(1), 1 ) + tb33 + CM( I1(5), 5 ) + CM( I1(7), 7 ) );
      tmp2a = CF( CM1( I0(0) ) + CM( I0(2), 2 ) + CM( I0(4), 4 ) + ta66 + CM( I0(8), 8 ) );
      tmp2b = CF( CM1( I1(0) ) + CM( I1(2), 2 ) + CM( I1(4), 4 ) + tb66 + CM( I1(8), 8 ) );
      MACRO1( 0 );
      MACRO2( 8 );
    }

    {
      IMDCT_TYPE tmp1a,tmp2a,tmp1b,tmp2b;
      tmp1a = CF( CM( I0(1) - I0(5) - I0(7), 3 ) );
      tmp1b = CF( CM( I1(1) - I1(5) - I1(7), 3 ) );
      tmp2a = CF( CM( I0(2) - I0(4) - I0(8), 6 ) + CM1( I0(0) - I0(6) ) );
      tmp2b = CF( CM( I1(2) - I1(4) - I1(8), 6 ) + CM1( I1(0) - I1(6) ) );
      MACRO1( 1 );
      MACRO2( 7 );
    }

    {
      IMDCT_TYPE tmp1a,tmp2a,tmp1b,tmp2b;
      tmp1a = CF( CM( I0(1), 5 ) - ta33 - CM( I0(5), 7 ) + CM( I0(7), 1 ) );
      tmp1b = CF( CM( I1(1), 5 ) - tb33 - CM( I1(5), 7 ) + CM( I1(7), 1 ) );
      tmp2a = CF( CM1( I0(0) ) - CM( I0(2), 8 ) - CM( I0(4), 2 ) + ta66 + CM( I0(8), 4 ) );
      tmp2b = CF( CM1( I1(0) ) - CM( I1(2), 8 ) - CM( I1(4), 2 ) + tb66 + CM( I1(8), 4 ) );
      MACRO1( 2 );
      MACRO2( 6 );
    }

    {
      IMDCT_TYPE tmp1a,tmp2a,tmp1b,tmp2b;
      tmp1a = CF( CM( I0(1), 7 ) - ta33 + CM( I0(5), 1 ) - CM( I0(7), 5 ) );
      tmp1b = CF( CM( I1(1), 7 ) - tb33 + CM( I1(5), 1 ) - CM( I1(7), 5 ) );
      tmp2a = CF( CM1( I0(0) ) - CM( I0(2), 4 ) + CM( I0(4), 8 ) + ta66 - CM( I0(8), 2 ) );
      tmp2b = CF( CM1( I1(0) ) - CM( I1(2), 4 ) + CM( I1(4), 8 ) + tb66 - CM( I1(8), 2 ) );
      MACRO1( 3 );
      MACRO2( 5 );
    }

    {
      IMDCT_TYPE sum0,sum1;
      sum0 =  CF( CM1( I0(0) - I0(2) + I0(4) - I0(6) + I0(8) ) );
      sum1 = T36_MULT( CF( CM1( I1(0) - I1(2) + I1(4) - I1(6) + I1(8) ) ), 4  );
      MACRO0( 4 );
    }
  }
}


static void dct12( MPEGAUD_FRACT_TYPE *in, MPEGIMDCT_BLOCK_TYPE *prev,
                   WIN_TYPE *w, MPEGAUD_FRACT_TYPE *ts )
{
#define DCT12_PART1 \
             in5 = in[5*3];  \
     in5 += (in4 = in[4*3]); \
     in4 += (in3 = in[3*3]); \
     in3 += (in2 = in[2*3]); \
     in2 += (in1 = in[1*3]); \
     in1 += (in0 = in[0*3]); \
                             \
     in5 += in3; in3 += in1; \
                             \
     in2 = COS_MULT( in2, COS6_1 ); \
     in3 = COS_MULT( in3, COS6_1 ); \

#define DCT12_PART2 \
     in0 += COS_MULT( in4, COS6_2 ); \
                          \
     in4 = in0 + in2;     \
     in0 -= in2;          \
                          \
     in1 += COS_MULT( in5, COS6_2 ); \
                          \
     in5 = T12_MULT( (in1 + in3), 0 ); \
     in1 = T12_MULT( (in1 - in3), 2 ); \
                         \
     in3 = in4 + in5;    \
     in4 -= in5;         \
                         \
     in2 = in0 + in1;    \
     in0 -= in1;


   {
     IMDCT_TYPE in0,in1,in2,in3,in4,in5;
     ts[SBLIMIT*0] = prev[0]; ts[SBLIMIT*1] = prev[1]; ts[SBLIMIT*2] = prev[2];
     ts[SBLIMIT*3] = prev[3]; ts[SBLIMIT*4] = prev[4]; ts[SBLIMIT*5] = prev[5];

     DCT12_PART1

     {
       IMDCT_TYPE tmp0,tmp1 = (in0 - in4);
       {
         IMDCT_TYPE tmp2 = T12_MULT( (in1 - in5), 1 );
         tmp0 = tmp1 + tmp2;
         tmp1 -= tmp2;
       }
       ts[(17-1)*SBLIMIT] = prev[17-1] + WIN_MULT( tmp0, 11-1 );
       ts[(12+1)*SBLIMIT] = prev[12+1] + WIN_MULT( tmp0, 6+1 );
       ts[(6 +1)*SBLIMIT] = prev[6 +1] + WIN_MULT( tmp1, 1 );
       ts[(11-1)*SBLIMIT] = prev[11-1] + WIN_MULT( tmp1, 5-1 );
     }

     DCT12_PART2

     ts[(17-0)*SBLIMIT] = prev[17-0] + WIN_MULT( in2, 11-0 );
     ts[(12+0)*SBLIMIT] = prev[12+0] + WIN_MULT( in2, 6+0 );
     ts[(12+2)*SBLIMIT] = prev[12+2] + WIN_MULT( in3, 6+2 );
     ts[(17-2)*SBLIMIT] = prev[17-2] + WIN_MULT( in3, 11-2 );

     ts[(6+0)*SBLIMIT]  = prev[6+0]  + WIN_MULT( in0, 0 );
     ts[(11-0)*SBLIMIT] = prev[11-0] + WIN_MULT( in0, 5-0 );
     ts[(6+2)*SBLIMIT]  = prev[6+2]  + WIN_MULT( in4, 2 );
     ts[(11-2)*SBLIMIT] = prev[11-2] + WIN_MULT( in4, 5-2 );
  }

  in++;

  {
     IMDCT_TYPE in0,in1,in2,in3,in4,in5;

     DCT12_PART1

     {
       IMDCT_TYPE tmp0,tmp1 = (in0 - in4);
       {
         IMDCT_TYPE tmp2 = T12_MULT( (in1 - in5), 1 );
         tmp0 = tmp1 + tmp2;
         tmp1 -= tmp2;
       }
       prev[5-1] = WIN_MULT( tmp0, 11-1 );
       prev[0+1] = WIN_MULT( tmp0, 6+1 );
       ts[(12+1)*SBLIMIT] += WIN_MULT( tmp1, 1 );
       ts[(17-1)*SBLIMIT] += WIN_MULT( tmp1, 5-1 );
     }

     DCT12_PART2

     prev[5-0] = WIN_MULT( in2, 11-0 );
     prev[0+0] = WIN_MULT( in2, 6+0 );
     prev[0+2] = WIN_MULT( in3, 6+2 );
     prev[5-2] = WIN_MULT( in3, 11-2 );

     ts[(12+0)*SBLIMIT] += WIN_MULT( in0, 0 );
     ts[(17-0)*SBLIMIT] += WIN_MULT( in0, 5-0 );
     ts[(12+2)*SBLIMIT] += WIN_MULT( in4, 2 );
     ts[(17-2)*SBLIMIT] += WIN_MULT( in4, 5-2 );
  }

  in++;

  {
     IMDCT_TYPE in0,in1,in2,in3,in4,in5;
     prev[12]=prev[13]=prev[14]=prev[15]=prev[16]=prev[17]=(MPEGIMDCT_BLOCK_TYPE)0;

     DCT12_PART1

     {
       IMDCT_TYPE tmp0,tmp1 = (in0 - in4);
       {
         IMDCT_TYPE tmp2 = T12_MULT( (in1 - in5), 1 );
         tmp0 = tmp1 + tmp2;
         tmp1 -= tmp2;
       }
       prev[11-1] = WIN_MULT( tmp0, 11-1 );
       prev[6 +1] = WIN_MULT( tmp0, 6+1 );
       prev[0+1] += WIN_MULT( tmp1, 1 );
       prev[5-1] += WIN_MULT( tmp1, 5-1 );
     }

     DCT12_PART2

     prev[11-0] = WIN_MULT( in2, 11-0 );
     prev[6 +0] = WIN_MULT( in2, 6+0 );
     prev[6 +2] = WIN_MULT( in3, 6+2 );
     prev[11-2] = WIN_MULT( in3, 11-2 );

     prev[0+0] += WIN_MULT( in0, 0 );
     prev[5-0] += WIN_MULT( in0, 5-0 );
     prev[0+2] += WIN_MULT( in4, 2 );
     prev[5-2] += WIN_MULT( in4, 5-2 );
  }
}

int MPEGIMDCT_hybrid( MPEGIMDCT *mpegimdct, MPEGAUD_FRACT_TYPE *in,
                      MPEGAUD_FRACT_TYPE *out, INT16 block_type, BOOL mixed,
                      INT16 ch, INT16 sb_max )
/*--------------------------------------------------------------------------
   Apply the hybrid imdct to a granule
   Return 0 if Ok
*/
{
   static BOOL init = FALSE;
   MPEGIMDCT_BLOCK_TYPE *prev;
   INT16 bt1,bt2;
   INT16 sb;

#define O( i ) out[ i*32 ]

   if( !init ) {
      int i,j;
#ifdef IMDCT_INT
#define KW ((double)(1<<(WIN_BITS-1))+0)
#define KC (double)(1<<COS_BITS)
#define KT ((double)(1<<(TFC_BITS-1))+0)
#else
#define KW 0.5
#define KC 1
#define KT 0.5
#endif

      for(i=0;i<18;i++) {
         win[0][i]    = win[1][i]    = KW * sin( M_PI / 72.0 * (double) (2*(i+0) +1) ) / cos ( M_PI * (double) (2*(i+0) +19) / 72.0 );
         win[0][i+18] = win[3][i+18] = KW * sin( M_PI / 72.0 * (double) (2*(i+18)+1) ) / cos ( M_PI * (double) (2*(i+18)+19) / 72.0 );
      }
      for(i=0;i<6;i++) {
         win[1][i+18] = KW / cos ( M_PI * (double) (2*(i+18)+19) / 72.0 );
         win[3][i+12] = KW / cos ( M_PI * (double) (2*(i+12)+19) / 72.0 );
         win[1][i+24] = KW * sin( M_PI / 24.0 * (double) (2*i+13) ) / cos ( M_PI * (double) (2*(i+24)+19) / 72.0 );
         win[1][i+30] = win[3][i] = 0.0;
         win[3][i+6 ] = KW * sin( M_PI / 24.0 * (double) (2*i+1) )  / cos ( M_PI * (double) (2*(i+6 )+19) / 72.0 );
      }

      for(i=0;i<9;i++) COS9[i] = KC * cos( M_PI / 18.0 * (double) i);

      for(i=0;i<9;i++) tfcos36[i] = KT / cos ( M_PI * (double) (i*2+1) / 36.0 );
      for(i=0;i<3;i++) tfcos12[i] = KT / cos ( M_PI * (double) (i*2+1) / 12.0 );

      COS6_1 = KC * cos( M_PI / 6.0 * (double) 1 );
      COS6_2 = KC * cos( M_PI / 6.0 * (double) 2 );

      for(i=0;i<12;i++) {
         win[2][i]  = KW * sin( M_PI / 24.0 * (double) (2*i+1) ) / cos ( M_PI * (double) (2*i+7) / 24.0 );
         for(j=0;j<6;j++) COS1[i][j] = KC * cos( M_PI / 24.0 * (double) ((2*i+7)*(2*j+1)) );
      }

      for(j=0;j<4;j++) {
         static const int len[4] = { 36,36,12,36 }; /* #3 Added const */
         for(i=0;i<len[j];i+=2) win1[j][i] = + win[j][i];
         for(i=1;i<len[j];i+=2) win1[j][i] = - win[j][i];
      }
      init = TRUE;

   }

   prev = mpegimdct->prevblk[ ch ];

   bt1 = (mixed) ? 0 : block_type;
   bt2 = block_type;

   if( bt2 == 2 ) {
      if( !bt1 ) {
         dct36( in, prev, win[0], out );
         in += SSLIMIT;
         dct36( in, prev+18, win1[0], out+1 );
         in += SSLIMIT;
      }
      else {
         dct12( in, prev, win[2], out );
         in += SSLIMIT;
         dct12( in, prev+18, win1[2], out+1 );
         in += SSLIMIT;
      }
      prev += 36; out += 2;
      for( sb=2; sb<sb_max; sb += 2,out += 2, prev += 36 ) {
         dct12( in, prev, win[2], out );
         in += SSLIMIT;
         dct12( in, prev+18, win1[2], out+1 );
         in += SSLIMIT;
      }
   }
   else {
      dct36( in, prev, win[bt1], out );
      in += SSLIMIT;
      dct36( in, prev+18, win1[bt1], out+1 );
      in += SSLIMIT;
      prev += 36; out += 2;
      for ( sb=2; sb<sb_max; sb += 2, out += 2, prev += 36 ) {
         dct36( in, prev, win[bt2], out );
         in += SSLIMIT;
         dct36( in, prev+18, win1[bt2], out+1 );
         in += SSLIMIT;
      }
   }

   for( ; sb< SBLIMIT; sb++ ) {
      O( 0 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 1 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 2 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
      O( 3 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 4 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 5 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
      O( 6 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 7 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 8 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
      O( 9 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 10 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 11 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
      O( 12 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 13 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 14 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
      O( 15 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 16 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
          O( 17 ) = *prev; *prev++ = (MPEGIMDCT_BLOCK_TYPE)0;
      out++;
   }

   return 0;
}


#else // -> NOT NEW_IMDCT


#ifndef PI
#define PI 3.14159265358979323846
#endif

#ifdef IMDCT_INT
#define IMDCT_IO_TYPE MPEGAUD_FRACT_TYPE
#define IMDCT_TYPE INT32
#define IMDCT_BITS 14
#define WIN_TYPE INT16
#define WIN_BITS 14
#define WIN_MULT( t, w ) (((t) * (w))>>WIN_BITS)
#else
#define IMDCT_IO_TYPE REAL
#define IMDCT_TYPE REAL
#define IMDCT_BITS 0
#define WIN_TYPE REAL
#define WIN_BITS 0
#define WIN_MULT( t, w ) ((t) * (w))
#endif



static int imdct_l( IMDCT_IO_TYPE *x, IMDCT_IO_TYPE *out,
                    MPEGIMDCT_BLOCK_TYPE *prev, WIN_TYPE *win )
{
   static const IMDCT_TYPE K0 = 0.9990482216 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K1 = 0.9914448614 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K2 = 0.9762960071 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K3 = 0.9537169507 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K4 = 0.9238795325 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K5 = 0.8870108332 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K6 = 0.8433914458 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K7 = 0.7933533403 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K8 = 0.7372773368 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K9 = 0.6755902076 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K10 = 0.6087614290 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K11 = 0.5372996083 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K12 = 0.4617486132 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K13 = 0.3826834324 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K14 = 0.3007057995 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K15 = 0.2164396139 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K16 = 0.1305261922 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K17 = 0.04361938737 * (1<<IMDCT_BITS); /* #3 Added const */

   IMDCT_TYPE k1, k2;
   IMDCT_TYPE s[ 6 ];
   IMDCT_TYPE t[ 6 ];
   IMDCT_TYPE temp;
   INT16 i;
#ifdef IMDCT_INT
#define S( a ) (INT32)x[ a ] - (INT32)x[ 11-a ] - (INT32)x[ 12+a ]
//   #define M( xi, Kx ) ((INT32)x[ xi ] * (Kx))
#define M( xi, Kx ) (x[ xi ] * (Kx))
#define MT( ti, Kx ) (t[ ti ] * (Kx))
#define W( t, wi ) WIN_MULT( (t>>IMDCT_BITS), win[ wi ] )
#else
#define S( a ) x[ a ] - x[ 11-a ] - x[ 12+a ]
#define M( xi, Kx ) (REAL)(x[ xi ] * (Kx))
#define MT( ti, Kx ) (REAL)(t[ ti ] * (Kx))
#define W( t, wi ) (REAL)(t * win[ wi ])
#endif

#define O( i ) out[ i*32 ]

   k1 = M( 4, K13 ) - M( 13, K4 );
   k2 = M( 4, K4 )  + M( 13, K13 );

   s[ 0 ] = -M( 1, K7 )  + k1 + M( 7, K1 )  + M( 10, K16 ) - M( 16, K10 );
   s[ 1 ] = -M( 1, K4 )  - k1 + M( 7, K13 ) + M( 10, K4 )  + M( 16, K13 );
   s[ 2 ] = -M( 1, K1 )  - k2 - M( 7, K7 )  - M( 10, K10 ) - M( 16, K16 );

   s[ 3 ] = -M( 1, K10 ) + k2 + M( 7, K16 ) - M( 10, K1 )  + M( 16, K7 );
   s[ 4 ] = -M( 1, K13 ) + k2 - M( 7, K4 )  + M( 10, K13 ) - M( 16, K4 );
   s[ 5 ] = -M( 1, K16 ) + k1 - M( 7, K10 ) + M( 10, K7 )  + M( 16, K1 );

   t[ 0 ] = S( 0 );
   t[ 1 ] = S( 2 );
   t[ 2 ] = S( 3 );
   t[ 3 ] = S( 5 );

   // 0
   temp =   M( 0, K9 ) - M( 2, K11 ) + M( 3, K5 )   - M( 5, K3 )   - M( 6, K15 ) + M( 8, K17 )
          - M( 9, K0 ) + M( 11, K2 ) - M( 12, K14 ) + M( 14, K12 ) + M( 15, K6 ) - M( 17, K8 );
   temp += s[ 0 ];
   O( 0 ) = prev[ 0 ] + W( temp, 0 );   O( 17 ) = prev[ 17 ] -W( temp, 17 );
   // 1
   temp =   MT( 0, K10 ) - MT( 1, K16 ) + MT( 2, K1 ) - MT( 3, K7 ) + s[ 1 ];
   O( 1 ) = prev[ 1 ] + W( temp, 1 );   O( 16 ) =  prev[ 16 ] -W( temp, 16 );
   // 2
   temp =   M( 0, K11 ) + M( 2, K14 ) + M( 3, K8 )  + M( 5, K17 ) + M( 6, K5 )  - M( 8, K15 )
          + M( 9, K2 ) - M( 11, K12 ) + M( 12, K0 ) - M( 14, K9 ) + M( 15, K3 ) - M( 17, K6 );
   temp += s[ 2 ];
   O( 2 ) = prev[ 2 ] + W( temp, 2 );   O( 15 ) = prev[ 15 ] -W( temp, 15 );
   // 3
   temp =   M( 0, K12 ) + M( 2, K9 ) + M( 3, K15 )  + M( 5, K6 ) - M( 6, K17 )  + M( 8, K3 )
          - M( 9, K14 ) + M( 11, K0 ) - M( 12, K11 ) + M( 14, K2 ) - M( 15, K8 ) + M( 17, K5 );
   temp += s[ 2 ];
   O( 3 ) = prev[ 3 ] + W( temp, 3 );   O( 14 ) = prev[ 14 ] -W( temp, 14 );
   // 4
   temp =   MT( 0, K13 ) + MT( 1, K4 ) - MT( 2, K13 ) + MT( 3, K4 ) + s[ 1 ];
   O( 4 ) = prev[ 4 ] + W( temp, 4 );   O( 13 ) = prev[ 13 ]  -W( temp, 13 );
   // 5
   temp =   M( 0, K14 ) + M( 2, K0 ) - M( 3, K6 )  + M( 5, K15 ) - M( 6, K8 )  - M( 8, K5 )
          + M( 9, K12 ) - M( 11, K9 ) + M( 12, K2 ) + M( 14, K11 ) + M( 15, K17 ) + M( 17, K3 );
   temp += s[ 0 ];
   O( 5 ) = prev[ 5 ] + W( temp, 5 );   O( 12 ) = prev[ 12 ] -W( temp, 12 );
   // 6
   temp =   M( 0, K15 ) + M( 2, K5 ) - M( 3, K0 )  - M( 5, K9 ) + M( 6, K14 )  - M( 8, K11 )
          + M( 9, K6 ) + M( 11, K3 ) - M( 12, K8 ) + M( 14, K17 ) - M( 15, K12 ) - M( 17, K2 );
   temp += s[ 3 ];
   O( 6 ) = prev[ 6 ] + W( temp, 6 );   O( 11 ) = prev[ 11 ] -W( temp, 11 );
   // 7
   temp =   MT( 0, K16 ) + MT( 1, K10 ) - MT( 2, K7 ) - MT( 3, K1 ) + s[ 4 ];
   O( 7 ) = prev[ 7 ] + W( temp, 7 );   O( 10 ) = prev[ 10 ] -W( temp, 10 );
   // 8
   temp =   M( 0, K17 ) + M( 2, K15 ) - M( 3, K14 ) - M( 5, K12 ) + M( 6, K11 ) + M( 8, K9 )
          - M( 9, K8 ) - M( 11, K6 ) + M( 12, K5 ) + M( 14, K3 ) - M( 15, K2 ) - M( 17, K0 );
   temp += s[ 5 ];
   O( 8 ) = prev[ 8 ] + W( temp, 8 );   O( 9 ) = prev[ 9 ] -W( temp, 9 );

   // 9+9
   temp = - M( 0, K8 ) + M( 2, K6 ) - M( 3, K12 ) + M( 5, K14 ) + M( 6, K2 ) - M( 8, K0 )
          - M( 9, K17 ) + M( 11, K15 ) - M( 12, K3 ) + M( 14, K5 ) + M( 15, K11 ) - M( 17, K9 );
   temp -= s[ 3 ];
   prev[ 0 ] = W( temp, 18 );   prev[ 17 ] = W( temp, 35 );
   // 10+9
   temp =  - MT( 0, K7 ) + MT( 1, K1 ) + MT( 2, K16 ) - MT( 3, K10 ) - s[ 4 ];
   prev[ 1 ] = W( temp, 19 );   prev[ 16 ] = W( temp, 34 );
   // 11+9
   temp = - M( 0, K6 ) + M( 2, K3 ) + M( 3, K9 ) - M( 5, K0 ) - M( 6, K12 ) + M( 8, K2 )
          + M( 9, K15 ) - M( 11, K5 ) + M( 12, K17 ) + M( 14, K8 ) - M( 15, K14 ) - M( 17, K11 );
   temp -= s[ 5 ];
   prev[ 2 ] = W( temp, 20 );   prev[ 15 ] = W( temp, 33 );
   // 12+9
   temp = - M( 0, K5 ) + M( 2, K8 ) + M( 3, K2 ) - M( 5, K11 ) - M( 6, K0 ) + M( 8, K14 )
          + M( 9, K3 ) - M( 11, K17 ) - M( 12, K6 ) - M( 14, K15 ) + M( 15, K9 ) + M( 17, K12 );
   temp += s[ 5 ];
   prev[ 3 ] = W( temp, 21 );   prev[ 14 ] = W( temp, 32 );
   // 13+9
   temp =  - MT( 0, K4 ) + MT( 1, K13 ) + MT( 2, K4 ) + MT( 3, K13 ) + s[ 4 ];
   prev[ 4 ] = W( temp, 22 );   prev[ 13 ] = W( temp, 31 );
   // 14+9
   temp = - M( 0, K3 ) - M( 2, K17 ) + M( 3, K11 ) + M( 5, K2 ) + M( 6, K9 ) - M( 8, K12 )
          - M( 9, K5 ) - M( 11, K8 ) - M( 12, K15 ) + M( 14, K6 ) + M( 15, K0 ) + M( 17, K14 );
   temp += s[ 3 ];
   prev[ 5 ] = W( temp, 23 );   prev[ 12 ] = W( temp, 30 );
   // 15+9
   temp = - M( 0, K2 ) - M( 2, K12 ) - M( 3, K17 ) + M( 5, K8 ) + M( 6, K3 ) + M( 8, K6 )
          + M( 9, K11 ) - M( 11, K14 ) - M( 12, K9 ) - M( 14, K0 ) - M( 15, K5 ) - M( 17, K15 );
   temp += s[ 0 ];
   prev[ 6 ] = W( temp, 24 );   prev[ 11 ] = W( temp, 29 );
   // 16+9
   temp =  - MT( 0, K1 ) - MT( 1, K7 ) - MT( 2, K10 ) - MT( 3, K16 ) + s[ 1 ];
   prev[ 7 ] = W( temp, 25 );   prev[ 10 ] = W( temp, 28 );
   // 17+9
   temp = - M( 0, K0 ) - M( 2, K2 ) - M( 3, K3 ) - M( 5, K5 ) - M( 6, K6 ) - M( 8, K8 )
          - M( 9, K9 ) - M( 11, K11 ) - M( 12, K12 ) - M( 14, K14 ) - M( 15, K15 ) - M( 17, K17 );
   temp += s[ 2 ];
   prev[ 8 ] = W( temp, 26 );   prev[ 9 ] = W( temp, 27 );

   return 0;

#undef O
#undef set_k
#undef S
#undef W
#undef MT
#undef M

}

static int imdct_s( IMDCT_IO_TYPE *x, IMDCT_IO_TYPE *out,
                    MPEGIMDCT_BLOCK_TYPE *prev, WIN_TYPE *win )
{
   static const IMDCT_TYPE K0 = 0.9914448614 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K1 = 0.9238795325 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K2 = 0.7933533403 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K3 = 0.6087614290 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K4 = 0.3826834324 * (1<<IMDCT_BITS); /* #3 Added const */
   static const IMDCT_TYPE K5 = 0.1305261922 * (1<<IMDCT_BITS); /* #3 Added const */

   IMDCT_TYPE s[ 2 ];
   IMDCT_TYPE t[ 2 ];
   IMDCT_TYPE temp;
   INT16 i;
#ifdef IMDCT_INT
#define M( xi, Kx ) ((INT32)x[ (xi*3) ] * (Kx))
#define MT( ti, Kx ) (t[ ti ] * (Kx))
#define W( t, wi ) WIN_MULT( (t>>IMDCT_BITS), win[ wi ] )
#else
#define M( xi, Kx ) (REAL)(x[ (xi*3) ] * (Kx))
#define MT( ti, Kx ) (REAL)(t[ ti ] * (Kx))
#define W( t, wi ) (REAL)(t * win[ wi ])
#endif
#define O( i ) out[ i*32 ]

// Step 1
   O( 0 ) = prev[ 0 ]; O( 1 ) = prev[ 1 ]; O( 2 ) = prev[ 2 ];
   O( 3 ) = prev[ 3 ]; O( 4 ) = prev[ 4 ]; O( 5 ) = prev[ 5 ];

   s[ 0 ] = M( 1, K1 ) + M( 4, K4 );
   s[ 1 ] = M( 1, K4 ) - M( 4, K1 );

   t[ 0 ] =  x[0*3] - x[3*3];
   t[ 1 ] =  x[2*3] + x[5*3];
   // 0
   temp =   M( 0, K3 ) - M( 2, K5 ) + M( 3, K0 ) - M( 5, K2 ) - s[ 0 ];
   O( 6 ) = prev[ 6 ] + W( temp, 0 );   O( 11 ) = prev[ 11 ] -W( temp, 5 );
   // 1
   temp =   MT( 0, K4 ) + MT( 1, K1 ) - s[ 0 ];
   O( 7 ) = prev[ 7 ] + W( temp, 1 );   O( 10 ) = prev[ 10 ] -W( temp, 4 );
   // 2
   temp =   M( 0, K5 ) + M( 2, K3 ) - M( 3, K2 ) - M( 5, K0 ) - s[ 1 ];
   O( 8 ) = prev[ 8 ] + W( temp, 2 );   O( 9 ) = prev[ 9 ] -W( temp, 3 );
   // 3

   // 3+3
   temp = - M( 0, K2 ) + M( 2, K0 ) + M( 3, K5 ) - M( 5, K3 ) + s[ 1 ];
   O( 12 ) = W( temp, 6 );   O( 17 ) = W( temp, 11 );
   // 4+3
   temp = - MT( 0, K1 ) + MT( 1, K4 ) - s[ 1 ];
   O( 13 ) = W( temp, 7 );   O( 16 ) = W( temp, 10 );
   // 5+3
   temp = - M( 0, K0 ) - M( 2, K2 ) - M( 3, K3 ) - M( 5, K5 ) - s[ 0 ];
   O( 14 ) = W( temp, 8 );   O( 15 ) = W( temp, 9 );

// Step 2
   x++;

   s[ 0 ] = M( 1, K1 ) + M( 4, K4 );
   s[ 1 ] = M( 1, K4 ) - M( 4, K1 );

   t[ 0 ] =  x[0*3] - x[3*3];
   t[ 1 ] =  x[2*3] + x[5*3];
   // 0
   temp =   M( 0, K3 ) - M( 2, K5 ) + M( 3, K0 ) - M( 5, K2 ) - s[ 0 ];
   O( 12 ) += W( temp, 0 );   O( 17 ) += -W( temp, 5 );
   // 1
   temp =   MT( 0, K4 ) + MT( 1, K1 ) - s[ 0 ];
   O( 13 ) += W( temp, 1 );   O( 16 ) += -W( temp, 4 );
   // 2
   temp =   M( 0, K5 ) + M( 2, K3 ) - M( 3, K2 ) - M( 5, K0 ) - s[ 1 ];
   O( 14 ) += W( temp, 2 );   O( 15 ) += -W( temp, 3 );
   // 3

   // 3+3
   temp = - M( 0, K2 ) + M( 2, K0 ) + M( 3, K5 ) - M( 5, K3 ) + s[ 1 ];
   prev[ 0 ] = W( temp, 6 );   prev[ 5 ] = W( temp, 11 );
   // 4+3
   temp = - MT( 0, K1 ) + MT( 1, K4 ) - s[ 1 ];
   prev[ 1 ] = W( temp, 7 );   prev[ 4 ] = W( temp, 10 );
   // 5+3
   temp = - M( 0, K0 ) - M( 2, K2 ) - M( 3, K3 ) - M( 5, K5 ) - s[ 0 ];
   prev[ 2 ] = W( temp, 8 );   prev[ 3 ] = W( temp, 9 );

// Step 3
   x++;

   s[ 0 ] = M( 1, K1 ) + M( 4, K4 );
   s[ 1 ] = M( 1, K4 ) - M( 4, K1 );

   t[ 0 ] =  x[0*3] - x[3*3];
   t[ 1 ] =  x[2*3] + x[5*3];
   // 0
   temp =   M( 0, K3 ) - M( 2, K5 ) + M( 3, K0 ) - M( 5, K2 ) - s[ 0 ];
   prev[ 0 ] += W( temp, 0 );   prev[ 5 ] += -W( temp, 5 );
   // 1
   temp =   MT( 0, K4 ) + MT( 1, K1 ) - s[ 0 ];
   prev[ 1 ] += W( temp, 1 );   prev[ 4 ] += -W( temp, 4 );
   // 2
   temp =   M( 0, K5 ) + M( 2, K3 ) - M( 3, K2 ) - M( 5, K0 ) - s[ 1 ];
   prev[ 2 ] += W( temp, 2 );   prev[ 3 ] += -W( temp, 3 );
   // 3

   // 3+3
   temp = - M( 0, K2 ) + M( 2, K0 ) + M( 3, K5 ) - M( 5, K3 ) + s[ 1 ];
   prev[ 6 ] = W( temp, 6 );   prev[ 11 ] = W( temp, 11 );
   // 4+3
   temp = - MT( 0, K1 ) + MT( 1, K4 ) - s[ 1 ];
   prev[ 7 ] = W( temp, 7 );   prev[ 10 ] = W( temp, 10 );
   // 5+3
   temp = - M( 0, K0 ) - M( 2, K2 ) - M( 3, K3 ) - M( 5, K5 ) - s[ 0 ];
   prev[ 8 ] = W( temp, 8 );   prev[ 9 ] = W( temp, 9 );

   prev[ 12 ] = prev[ 13 ] = prev[ 14 ] =
   prev[ 15 ] = prev[ 16 ] = prev[ 17 ] = 0;

   return 0;

#undef O
#undef set_k
#undef W
#undef MT
#undef M
}


int MPEGIMDCT_hybrid( MPEGIMDCT *mpegimdct, MPEGAUD_FRACT_TYPE *in,
                      MPEGAUD_FRACT_TYPE *out, INT16 block_type, BOOL mixed,
                      INT16 ch, INT16 sb_max )
/*--------------------------------------------------------------------------
   Apply the hybrid imdct to a granule
   Return 0 if Ok
*/
{
#ifndef USE_IMDCT_TABLE
   static WIN_TYPE win[ 2 ][ 4 ][ 36 ];
#endif
   static BOOL init = FALSE;
   register MPEGIMDCT_BLOCK_TYPE *prev;
   INT16 sb;
   INT16 bt;
#ifdef IMDCT_TABLE_GEN
   static FILE *fdct_out;
   int i, j;
#endif

   if( !init ) {
      INT16 i, j;

#ifdef IMDCT_INT
#if !defined(USE_IMDCT_TABLE) || defined(IMDCT_TABLE_GEN)
      printf("Generating table values\n");
      // Block type 0
      for( i=0; i<36; i++ ) win[0][0][i] = sin( PI/36 * (i+0.5) ) * (1<<WIN_BITS);

      // Block type 1
      for( i=0;  i<18; i++ ) win[0][1][i] = sin( PI/36 * (i+0.5) ) * (1<<WIN_BITS);
      for( i=18; i<24; i++ ) win[0][1][i] = 1<<WIN_BITS;
      for( i=24; i<30; i++ ) win[0][1][i] = sin( PI/12 * (i+0.5-18) ) * (1<<WIN_BITS);
      for( i=30; i<36; i++ ) win[0][1][i] = 0;

      // Block type 3
      for( i=0;  i<6;  i++ ) win[0][3][i] = 0.0;
      for( i=6;  i<12; i++ ) win[0][3][i] = sin( PI/12 * (i+0.5-6) ) * (1<<WIN_BITS);
      for( i=12; i<18; i++ ) win[0][3][i] = 1<<WIN_BITS;
      for( i=18; i<36; i++ ) win[0][3][i] = sin( PI/36 * (i+0.5) ) * (1<<WIN_BITS);

      // Block type 2
      for( i=0;  i<12; i++) win[0][2][i] = sin( PI/12 * (i+0.5) ) * (1<<WIN_BITS);
      for( i=12; i<36; i++) win[0][2][i] = 0;

      for(j=0; j<4; j++) {
         for(i=0;i<36;i+=2) win[1][j][i] = +win[0][j][i];
         for(i=1;i<36;i+=2) win[1][j][i] = -win[0][j][i];
      }
#endif //if ~defined(USE_IMDCT_TABLE) || defined(IMDCT_TABLE_GEN)
#else 
      // Block type 0
      for( i=0; i<36; i++ ) win[0][0][i] = sin( PI/36 * (i+0.5) );

      // Block type 1
      for( i=0;  i<18; i++ ) win[0][1][i] = sin( PI/36 * (i+0.5) );
      for( i=18; i<24; i++ ) win[0][1][i] = 1.0;
      for( i=24; i<30; i++ ) win[0][1][i] = sin( PI/12 * (i+0.5-18) );
      for( i=30; i<36; i++ ) win[0][1][i] = 0.0;

      // Block type 3
      for( i=0;  i<6;  i++ ) win[0][3][i] = 0.0;
      for( i=6;  i<12; i++ ) win[0][3][i] = sin( PI/12 * (i+0.5-6) );
      for( i=12; i<18; i++ ) win[0][3][i] = 1.0;
      for( i=18; i<36; i++ ) win[0][3][i] = sin( PI/36 * (i+0.5) );

      // Block type 2
      for( i=0;  i<12; i++) win[0][2][i] = sin( PI/12 * (i+0.5) ) ;
      for( i=12; i<36; i++) win[0][2][i] = 0.0;

      for(j=0; j<4; j++) {
         for(i=0;i<36;i+=2) win[1][j][i] = +win[0][j][i];
         for(i=1;i<36;i+=2) win[1][j][i] = -win[0][j][i];
      }
#endif //#if IMDCT_INT
#ifdef IMDCT_TABLE_GEN

      fdct_out = fopen("imdct.out", "w");
      fprintf(fdct_out,"static short win[2][4][36] =\n{\n");
      fprintf(fdct_out,"  /* Start of table */\n  {\n", j);
      for(j=0; j<4; j++) {
	fprintf(fdct_out,"   /* Start of row %d */\n    {\n", j);
	for(i=0; i < 32; i = i + 4) {
	  fprintf(fdct_out,"      %d, %d, %d, %d, \n",
		win[0][j][i], win[0][j][i+1], win[0][j][i+2], win[0][j][i+3]);
	}
	// finish row, no comma at end
	fprintf(fdct_out,"      %d, %d, %d, %d \n",
		win[0][j][i], win[0][j][i+1], win[0][j][i+2], win[0][j][i+3]);
	fprintf(fdct_out,"    }, /* end of row %d */\n", j);
      }
      fprintf(fdct_out,"  },\n /* Start of second half of table */\n  {\n", j);
      for(j=0; j<4; j++) {
	fprintf(fdct_out,"    /* Start of row %d */\n    {\n", j);
	for(i=0; i < 32; i = i + 4) {
	  fprintf(fdct_out,"      %d, %d, %d, %d, \n",
		win[1][j][i], win[1][j][i+1], win[1][j][i+2], win[1][j][i+3]);
	}
	// finish row, no comma at end
	fprintf(fdct_out,"      %d, %d, %d, %d \n",
		win[1][j][i], win[1][j][i+1], win[1][j][i+2], win[1][j][i+3]);
	fprintf(fdct_out,"    }, /* end of row %d */\n", j);
      }
      fprintf(fdct_out,"  }\n/* End of second half of table */\n};\n", j);

      fclose(fdct_out);
#endif
      init = TRUE;
   }

#define O( i ) out[ i*32 ]

   prev = mpegimdct->prevblk[ ch ];
   for( sb=0; sb<sb_max; sb++ ) {
      bt = ((mixed) && (sb < 2)) ? 0 : block_type;

      if( bt == 2 ) { // Short block
         imdct_s( in, out, prev, &win[ sb & 1 ][ bt ][ 0 ] );
      }
      else {
         imdct_l( in, out, prev, &win[ sb & 1 ][ bt ][ 0 ] );
      }

      in += 18;
      out++;
      prev += 18;
   }

   for( ; sb<MPA_SBLIMIT; sb++ ) {
      // overlap addition with 0
      O( 0 ) = *prev; *prev++ = 0; O( 1 ) = *prev; *prev++ = 0; O( 2 ) = *prev; *prev++ = 0;
      O( 3 ) = *prev; *prev++ = 0; O( 4 ) = *prev; *prev++ = 0; O( 5 ) = *prev; *prev++ = 0;
      O( 6 ) = *prev; *prev++ = 0; O( 7 ) = *prev; *prev++ = 0; O( 8 ) = *prev; *prev++ = 0;
      O( 9 ) = *prev; *prev++ = 0; O( 10 ) = *prev; *prev++ = 0; O( 11 ) = *prev; *prev++ = 0;
      O( 12 ) = *prev; *prev++ = 0; O( 13 ) = *prev; *prev++ = 0; O( 14 ) = *prev; *prev++ = 0;
      O( 15 ) = *prev; *prev++ = 0; O( 16 ) = *prev; *prev++ = 0; O( 17 ) = *prev; *prev++ = 0;
      out++;
   }

MPEGAUD_CHECK_DEMO;

   return 0;

} /* MPEGIMDCT_hybrid */

#endif // NOT NEW_IMDCT

#endif // NOT ASM_OPTIMIZE

int MPEGIMDCT_reset( MPEGIMDCT *mpegimdct )
/*-----------------------------------------
   Reset the MPEGIMDCT module
*/
{
   if( !mpegimdct ) return -1;
   // Reset previous block buffer
   memset( mpegimdct->prevblk, 0, MPA_MAX_CHANNELS * MPA_GRANULE_SIZE * sizeof( MPEGIMDCT_BLOCK_TYPE ) );

   return 0;

} /* MPEGIMDCT_reset */


void MPEGIMDCT_close( MPEGIMDCT *mpegimdct )
/*------------------------------------------
   Close the MPEGIMDCT module
*/
{
   if( !mpegimdct ) return;
   free( mpegimdct );

} /* MPEGIMDCT_close */

MPEGIMDCT *MPEGIMDCT_open( void )
/*-------------------------------
   Open the MPEGIMDCT module
*/
{
   MPEGIMDCT *mpegimdct;

   mpegimdct = (MPEGIMDCT *)malloc( sizeof(MPEGIMDCT) );
   if( !mpegimdct ) return NULL;
   (void)MPEGIMDCT_reset( mpegimdct );

   return mpegimdct;

} /* MPEGIMDCT_open */


