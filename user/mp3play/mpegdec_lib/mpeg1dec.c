/*------------------------------------------------------------------------------

    File    :   MPEG1DEC.c

    Author  :   Stéphane TAVENARD

    $VER:   MPEG1DEC.c  0.3  (23/05/1997)

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
    0   |20/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |24/04/1997| Check forbidden values                               ST
    3   |23/05/1997| Added MPEGDEC_ERR_xxx                                ST

    ------------------------------------------------------------------------

    MPEG layer I decoding functions

------------------------------------------------------------------------------*/


#include "defs.h"
#include "bitstr.h"
#include "mpegaud.h"
#include "mpegtab.h"
#include "mpegsub.h"
#include "mpegdec.h"
#include "mpeg1dec.h"

static int MPEG1_decode_bitalloc( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the bit allocations of MPEG I stream
   Return 0 if Ok
*/
{
   INT16 sb;
   INT16 *bal0, *bal1;
   register INT16 value;
   BITSTREAM *bs = mps->bitstream;

   bal0 = &mps->bit_alloc[ 0 ][ 0 ];

   if( mps->stereo ) {
      bal1 = &mps->bit_alloc[ 1 ][ 0 ];
      for( sb=0; sb<mps->jsbound; sb++ ) {
         value = (INT16)BSTR_read_bits( bs, 8 );
         if( ((value & 0xF0) == 0xF0) || ((value & 0x0F) == 0x0F) ) return MPEGDEC_ERR_BADFRAME; // #2
         *bal0++ = (value >> 4) & 0xF;
         *bal1++ = value & 0xF;
      }
      for( ; sb<MPA_SBLIMIT; sb++ ) {
         *bal0 = BSTR_read_bits( bs, 4 );
         if( *bal0 == 0xF ) return MPEGDEC_ERR_BADFRAME; // #2
         *bal1++ = *bal0++;
      }
   }
   else {
      for( sb=0; sb<MPA_SBLIMIT; sb++ ) {
         value = BSTR_read_bits( bs, 4 );
         if( value == 0x0F ) return MPEGDEC_ERR_BADFRAME; // #2
         *bal0++ = value;
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG1_decode_bitalloc */

#ifdef MPEGAUD_INT
#define COEFF_TYPE INT32
#define COEFF_BITS 15

#define COEFF_MULTK( k, m ) ((coeff[ k ] * (m))>>(COEFF_BITS+MPEGTAB_MULT_BITS-MPEGAUD_SCALE_BITS))
// Precalc of 2*2^COEFF_BITS/(2^(k+1)-1)  k:0..15
// Rounded to lower value
static const COEFF_TYPE coeff[ 16 ] = {
   0, 21845, 9362, 4369, 2114, 1040, 516, 257,
   128, 64, 32, 16, 8, 4, 2, 1
};

#else

#define COEFF_MULTK( k, m ) (coeff[ k ] * (m))
// Precalc of 2/(2^(k+1)-1)  k:0..15
static const REAL coeff[ 16 ] = {
   2.0, 0.6666666667, 0.2857142857, 0.1333333333,
   0.06451612903, 0.03174603175, 0.0157480315, 7.843137255e-3,
   3.913894325e-3, 1.955034213e-3, 9.770395701e-4, 4.884004884e-4,
   2.441704310e-4, 1.220777635e-4, 6.103701895e-5, 3.051804379e-5
};

#endif

static int MPEG1_decode_scale( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the scales of MPEG I stream
   Return 0 if Ok
*/
{
   INT16 sb;
   INT16 *bal0, *bal1;
   MPEGAUD_SCALE_TYPE *sca0, *sca1;
   INT16 k;
   BITSTREAM *bs = mps->bitstream;

   sca0 = &mps->scale[ 0 ][ 0 ][ 0 ];
   bal0 = &mps->bit_alloc[ 0 ][ 0 ];

   if( mps->stereo ) {
      bal1 = &mps->bit_alloc[ 1 ][ 0 ];
      sca1 = &mps->scale[ 1 ][ 0 ][ 0 ];
      for( sb=0; sb<MPA_SBLIMIT; sb++ ) {
         k = *bal0++;
         if( k ) *sca0++ = COEFF_MULTK( k, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
         else    *sca0++ = (MPEGAUD_SCALE_TYPE)0;

         k = *bal1++;
         if( k ) *sca1++ = COEFF_MULTK( k, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
         else    *sca1++ = (MPEGAUD_SCALE_TYPE)0;
      }
   }
   else {
      for( sb=0; sb<MPA_SBLIMIT; sb++ ) {
         k = *bal0++;
         if( k ) *sca0++ = COEFF_MULTK( k, MPT_multiple[ BSTR_read_bits( bs, 6 ) ] );
         else    *sca0++ = (MPEGAUD_SCALE_TYPE)0;
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG1_decode_scale */

#ifdef MPEGAUD_INT
#define FRACT_MULT( sc, sa ) (((sc) * (sa))>>(MPEGAUD_SCALE_BITS-MPEGAUD_FRACT_BITS))
#else
#define FRACT_MULT( sc, sa ) ((sc) * (sa))
#endif

static int MPEG1_read_samples( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Read the samples of MPEG I stream & dequantize
   Return 0 if Ok
*/
{
   INT16 *bal0, *bal1;
   MPEGAUD_SCALE_TYPE *sca0, *sca1;
   MPEGAUD_FRACT_TYPE *fra0, *fra1;
   INT16 sb;
   INT16 k;
   INT32 s;
   BITSTREAM *bs = mps->bitstream;

   bal0 = &mps->bit_alloc[ 0 ][ 0 ];
   sca0 = &mps->scale[ 0 ][ 0 ][ 0 ];
   fra0 = &mps->fraction[ 0 ][ 0 ][ 0 ];

   if( mps->stereo ) {
      bal1 = &mps->bit_alloc[ 1 ][ 0 ];
      sca1 = &mps->scale[ 1 ][ 0 ][ 0 ];
      fra1 = &mps->fraction[ 1 ][ 0 ][ 0 ];
      for( sb=0; sb<mps->jsbound; sb++ ) {
         k = *bal0++;
         if( k ) {
            s = 1-(1<<k) + BSTR_read_bits( bs, k+1 );
            *fra0++ = FRACT_MULT( *sca0, s );
         }
         else *fra0++ = (MPEGAUD_SCALE_TYPE)0;
         sca0++;
         k = *bal1++;
         if( k ) {
            s = 1-(1<<k) + BSTR_read_bits( bs, k+1 );
            *fra1++ = FRACT_MULT( *sca1, s );
         }
         else *fra1++ = (MPEGAUD_SCALE_TYPE)0;
         sca1++;
      }
      for( ; sb<MPA_SBLIMIT; sb++ ) {
         k = *bal0++;
         if( k ) {
            s = 1-(1<<k) + BSTR_read_bits( bs, k+1 );
            *fra0++ = FRACT_MULT( *sca0, s );
            *fra1++ = FRACT_MULT( *sca1, s );
         }
         else *fra0++ = *fra1++ = (MPEGAUD_SCALE_TYPE)0;
         sca0++;
         sca1++;
      }
   }
   else {
      for( sb=0; sb<MPA_SBLIMIT; sb++ ) {
         k = *bal0++;
         if( k ) {
            s = 1-(1<<k) + BSTR_read_bits( bs, k+1 );
            *fra0++ = FRACT_MULT( *sca0, s );
         }
         else *fra0++ = (MPEGAUD_SCALE_TYPE)0;
         sca0++;
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG1_read_samples */

int MPEG1_reset( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Reset the decoder
*/
{
   return MPEGDEC_ERR_NONE;

} /* MPEG1_reset */

INT32 MPEG1_decode_frame( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the current frame
   Return # of decoded samples
*/
{
   INT16 block;
   INT16 ch;
   INT16 pcm_offset = 0;
   INT16 pcm_count = 0;
   INT16 channels = (mps->force_mono)?1:mps->channels;
   int err;

MPEGAUD_CHECK_DEMO;


   err = MPEG1_decode_bitalloc( mps );
   if( err ) return err;
   err = MPEG1_decode_scale( mps );
   if( err ) return err;

   for( block=0; block<MPA_SCALE_BLOCK; block++ ) {
      err = MPEG1_read_samples( mps );
      if( err ) return err;
      for( ch=0; ch<channels; ch++ ) {
         pcm_count = MPEGSUB_synthesis( mps->mpegsub, &mps->fraction[ch][0][0],
                                        ch, &mps->pcm[ ch ][ pcm_offset ] );
      }
      pcm_offset += pcm_count;
   }

   return (INT32)pcm_offset;

}
