/*------------------------------------------------------------------------------

    File    :   MPEG2DEC.c

    Author  :   Stéphane TAVENARD

    $VER:   MPEG2DEC.c  0.3  (23/05/1997)

    (C) Copyright 1997-1997 Stéphane TAVENARD
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
    0   |23/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |24/04/1997| Check forbidden values                               ST
    3   |23/05/1997| Added MPEGDEC_ERR_xxx                                ST

    ------------------------------------------------------------------------

    MPEG layer II decoding functions

------------------------------------------------------------------------------*/


#include "defs.h"
#include "bitstr.h"
#include "mpegaud.h"
#include "mpegtab.h"
#include "mpegsub.h"
#include "mpegdec.h"
#include "mpeg2dec.h"

static int MPEG2_decode_bitalloc( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the bit allocations of MPEG II stream
   Return 0 if Ok
*/
{
   INT16 sb;
   INT16 *bal0, *bal1;
   INT16 bits;
   register INT16 ba;
   BITSTREAM *bs = mps->bitstream;

   bal0 = &mps->bit_alloc[ 0 ][ 0 ];

   if( mps->stereo ) {
      bal1 = &mps->bit_alloc[ 1 ][ 0 ];
      for( sb=0; sb<mps->jsbound; sb++ ) {
         bits = mps->alloc[ sb ][ 0 ];
         ba = (INT16)BSTR_read_bits( bs, bits );
         if( ba ) {  // #2
            ba = mps->alloc[ sb ][ ba ];
            if( !ba ) return MPEGDEC_ERR_BADFRAME;
            *bal0++ = ba;
         }
         else *bal0++ = 0;
         ba = (INT16)BSTR_read_bits( bs, bits );
         if( ba ) {  // #2
            ba = mps->alloc[ sb ][ ba ];
            if( !ba ) return MPEGDEC_ERR_BADFRAME;
            *bal1++ = ba;
         }
         else *bal1++ = 0;
      }
      for( ; sb<mps->sblimit; sb++ ) {
         bits = mps->alloc[ sb ][ 0 ];
         ba = (INT16)BSTR_read_bits( bs, bits );
         if( ba ) {  // #2
            ba = mps->alloc[ sb ][ ba ];
            if( !ba ) return MPEGDEC_ERR_BADFRAME;
            *bal0 = ba;
         }
         else *bal0 = 0;
         *bal1++ = *bal0++;
      }
   }
   else {
      for( sb=0; sb<mps->sblimit; sb++ ) {
         ba = (INT16)BSTR_read_bits( bs, mps->alloc[ sb ][ 0 ] );
         if( ba ) {  // #2
            ba = mps->alloc[ sb ][ ba ];
            if( !ba ) return MPEGDEC_ERR_BADFRAME;
            *bal0++ = ba;
         }
         else *bal0++ = 0;
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG2_decode_bitalloc */

#ifdef MPEGAUD_INT
#define COEFF_TYPE INT32
#define COEFF_BITS 15
#define COEFF_MULT( c, m ) (((c) * (m))>>(COEFF_BITS+MPEGTAB_MULT_BITS-MPEGAUD_SCALE_BITS))

// Precalc of 2*2^COEFF_BITS/(2^(k+1)-1)  k:0..15
// Rounded to lower value
static const COEFF_TYPE coeff[ 16 ] = {
   0, 21845, 9362, 4369, 2114, 1040, 516, 257,
   128, 64, 32, 16, 8, 4, 2, 1
};

#else

#define COEFF_MULT( c, m ) ((c) * (m))
// Precalc of 2/(2^(k+1)-1)  k:0..15
static const REAL coeff[ 16 ] = {
   (REAL)2.0,            (REAL)0.6666666667,   (REAL)0.2857142857,   (REAL)0.1333333333,
   (REAL)0.06451612903,  (REAL)0.03174603175,  (REAL)0.0157480315,   (REAL)7.843137255e-3,
   (REAL)3.913894325e-3, (REAL)1.955034213e-3, (REAL)9.770395701e-4, (REAL)4.884004884e-4,
   (REAL)2.441704310e-4, (REAL)1.220777635e-4, (REAL)6.103701895e-5, (REAL)3.051804379e-5
};

#endif

static int MPEG2_decode_scale( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the scales of MPEG II stream
   Return 0 if Ok
*/
{
   INT16 sb, ch, ba;
   INT16 *bal0, *bal1;
   INT16 *scf0, *scf1;
   MPEGAUD_SCALE_TYPE *sca;
   MPEGAUD_SCALE_TYPE sc, co;
   BITSTREAM *bs = mps->bitstream;

   bal0 = &mps->bit_alloc[ 0 ][ 0 ];
   scf0 = &mps->scfsi[ 0 ][ 0 ];

   if( mps->stereo ) {
      bal1 = &mps->bit_alloc[ 1 ][ 0 ];
      scf1 = &mps->scfsi[ 1 ][ 0 ];
      for( sb=0; sb<mps->sblimit; sb++ ) {
         if( *bal0++ ) *scf0++ = (INT16)BSTR_read_bits( bs, 2 );
         else          *scf0++ = 0;

         if( *bal1++ ) *scf1++ = (INT16)BSTR_read_bits( bs, 2 );
         else          *scf1++ = 0;
      }
   }
   else {
      for( sb=0; sb<mps->sblimit; sb++ ) {
         if( *bal0++ ) *scf0++ = (INT16)BSTR_read_bits( bs, 2 );
         else          *scf0++ = 0;
      }
   }

MPEGAUD_CHECK_DEMO;

   for( sb=0; sb<mps->sblimit; sb++ ) {
      sca = &mps->scale[ 0 ][ 0 ][ sb ];
      for( ch=0; ch<mps->channels; ch++ ) {
         ba = mps->bit_alloc[ ch ][ sb ];
         if( ba ) {
            switch( ba & 0x30 ) {
               case 0x00: // No grouping
                  co = coeff[ ba ];
                  break;
#ifdef MPEGAUD_INT
               case 0x10: // Grouping 3/3/3
                  co = 21845;
                  break;
               case 0x20: // Grouping 5/5/5
                  co = 13107;
                  break;
               default:   // Grouping 9/9/9
                  co = 7281;
                  break;
#else
               case 0x10: // Grouping 3/3/3
                  co = (MPEGAUD_SCALE_TYPE)(2.0/3.0);
                  break;
               case 0x20: // Grouping 5/5/5
                  co = (MPEGAUD_SCALE_TYPE)(2.0/5.0);
                  break;
               default:   // Grouping 9/9/9
                  co = (MPEGAUD_SCALE_TYPE)(2.0/9.0);
                  break;
#endif
            }
            switch( mps->scfsi[ ch ][ sb ] ) {
                case 0 : // All three scale factors transmitted
                    *sca = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    sca += MPA_SBLIMIT;
                    *sca = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    sca += MPA_SBLIMIT;
                    *sca = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    sca += MPA_SBLIMIT;
                    break;
                case 1 : // Scale factor 1 & 3 transmitted
                    sc = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    *sca = sc; sca += MPA_SBLIMIT;
                    *sca = sc; sca += MPA_SBLIMIT;
                    *sca = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    sca += MPA_SBLIMIT;
                    break;
                case 3 : // Scale factor 1 & 2 transmitted
                    *sca = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    sca += MPA_SBLIMIT;
                    sc = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    *sca = sc; sca += MPA_SBLIMIT;
                    *sca = sc; sca += MPA_SBLIMIT;
                    break;
                case 2 : // Only one scale factor transmitted
                    sc = COEFF_MULT( co, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
                    *sca = sc; sca += MPA_SBLIMIT;
                    *sca = sc; sca += MPA_SBLIMIT;
                    *sca = sc; sca += MPA_SBLIMIT;
                    break;
                default :
                    break;
            }
         }
         else {
            *sca = (MPEGAUD_SCALE_TYPE)0; sca += MPA_SBLIMIT;
            *sca = (MPEGAUD_SCALE_TYPE)0; sca += MPA_SBLIMIT;
            *sca = (MPEGAUD_SCALE_TYPE)0; sca += MPA_SBLIMIT;
         }
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG2_decode_scale */

#ifdef MPEGAUD_INT
#define FRACT_MULT( sc, sa ) (((sc) * (sa))>>(MPEGAUD_SCALE_BITS-MPEGAUD_FRACT_BITS))
#else
#define FRACT_MULT( sc, sa ) ((sc) * (sa))
#endif

static int MPEG2_read_samples( MPA_STREAM *mps, INT16 scb )
/*--------------------------------------------------------------------------
   Read the samples of MPEG II stream & dequantize
   Return 0 if Ok
*/
{
   static UINT16 c3[ 32 ];
   static UINT16 c5[ 128 ];
   static UINT16 c9[ 1024 ];
   static BOOL init = FALSE;

   INT16 sb, ch;
   INT16 ba, k;
   UINT16 c;
   INT32 k2, s0, s1, s2;
   MPEGAUD_SCALE_TYPE m;
   MPEGAUD_FRACT_TYPE *fra;
   BITSTREAM *bs = mps->bitstream;

   if( !init ) {
      init = TRUE;
      for( k=0; k<32; k++ ) {
         c = k;
         c3[ k ] = (UINT16)(c % 3);
         c3[ k ] |= ((c /= 3) % 3)<<2;
         c3[ k ] |= ((c /= 3) % 3)<<4;
      }
      for( k=0; k<128; k++ ) {
         c = k;
         c5[ k ] = (UINT16)(c % 5);
         c5[ k ] |= ((c /= 5) % 5)<<4;
         c5[ k ] |= ((c /= 5) % 5)<<8;
      }
      for( k=0; k<1024; k++ ) {
         c = k;
         c9[ k ] = (UINT16)(c % 9);
         c9[ k ] |= ((c /= 9) % 9)<<4;
         c9[ k ] |= ((c /= 9) % 9)<<8;
      }
   }

MPEGAUD_CHECK_DEMO;

   scb >>= 2;

   for( sb=0; sb<mps->sblimit; sb++ ) {
      fra = &mps->fraction[ 0 ][ 0 ][ sb ];
      for( ch=0; ch<mps->channels; ch++ ) {
MPEGAUD_CHECK_DEMO;
         ba = mps->bit_alloc[ ch ][ sb ];
         m = mps->scale[ ch ][ scb ][ sb ];
         if( ba ) {
            k = (INT16)(ba & 0x0F);
            c = (UINT16)BSTR_read_bits( bs, k+1 );
            switch( ba & 0x30 ) {
                case 0x00: // No grouping
                   k2 = 1 - (1<<k);
                   s0 = k2 + c;
                   s1 = k2 + BSTR_read_bits( bs, k+1 );
                   s2 = k2 + BSTR_read_bits( bs, k+1 );
                   break;
                case 0x10:
                   c = c3[ c ];
                   s0 = (c & 0x03) - 1;
                   s1 = ((c>>2) & 0x03) - 1;
                   s2 = ((c>>4) & 0x03) - 1;
                   break;
                case 0x20:
                   c = c5[ c ];
                   s0 = (c & 0x000F) - 2;
                   s1 = ((c>>4) & 0x000F) - 2;
                   s2 = ((c>>8) & 0x000F) - 2;
                   break;
               default:
                   c = c9[ c ];
                   s0 = (c & 0x000F) - 4;
                   s1 = ((c>>4) & 0x000F) - 4;
                   s2 = ((c>>8) & 0x000F) - 4;
                   break;
            }
            *fra = FRACT_MULT( m, s0 ); fra += MPA_SBLIMIT;
            *fra = FRACT_MULT( m, s1 ); fra += MPA_SBLIMIT;
            *fra = FRACT_MULT( m, s2 ); fra += MPA_SBLIMIT;
            if( sb >= mps->jsbound && (mps->stereo) ) {
               m = mps->scale[ 1 ][ scb ][ sb ];
               *fra = FRACT_MULT( m, s0 ); fra += MPA_SBLIMIT;
               *fra = FRACT_MULT( m, s1 ); fra += MPA_SBLIMIT;
               *fra = FRACT_MULT( m, s2 ); // fra += MPA_SBLIMIT; Remove becoz of break !
               break;
            }
         }
         else {
            *fra = (MPEGAUD_FRACT_TYPE)0; fra += MPA_SBLIMIT;
            *fra = (MPEGAUD_FRACT_TYPE)0; fra += MPA_SBLIMIT;
            *fra = (MPEGAUD_FRACT_TYPE)0; fra += MPA_SBLIMIT;
            if( sb >= mps->jsbound && (mps->stereo) ) {
               *fra = (MPEGAUD_FRACT_TYPE)0; fra += MPA_SBLIMIT;
               *fra = (MPEGAUD_FRACT_TYPE)0; fra += MPA_SBLIMIT;
               *fra = (MPEGAUD_FRACT_TYPE)0; // fra += MPA_SBLIMIT; Remove becoz of break !
               break;
            }
         }
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG2_read_samples */

int MPEG2_reset( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Reset the decoder
*/
{
   if( !mps ) return MPEGDEC_ERR_MEM;
   return MPEGDEC_ERR_NONE;

} /* MPEG2_reset */

INT32 MPEG2_decode_frame( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the current frame
   Return # of decoded samples
*/
{
   INT16 scb;
   INT16 ch, gr;
   INT16 pcm_offset = 0;
   INT16 pcm_count = 0;
   INT16 channels = (INT16)((mps->force_mono)?1:mps->channels);
   int err;

MPEGAUD_CHECK_DEMO;

   err = MPEG2_decode_bitalloc( mps );
   if( err ) return err;
   err = MPEG2_decode_scale( mps );
   if( err ) return err;

   for( scb=0; scb<MPA_SCALE_BLOCK; scb++ ) {
      err = MPEG2_read_samples( mps, scb );
      if( err ) return err;
      for( gr=0; gr<MPA_GROUPS; gr++ ) {
         for( ch=0; ch<channels; ch++ ) {
            pcm_count = MPEGSUB_synthesis( mps->mpegsub, &mps->fraction[ch][gr][0],
                                           ch, &mps->pcm[ ch ][ pcm_offset ] );
         }
         pcm_offset += pcm_count;
      }
   }

   return (INT32)pcm_offset;

} /* MPEG2_decode_frame */

