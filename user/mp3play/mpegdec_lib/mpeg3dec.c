/*------------------------------------------------------------------------------

    File    :   MPEG3DEC.c

    Author  :   Stéphane TAVENARD

    $VER:   MPEG3DEC.c  1.1  (24/05/1999)

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
    0   |15/03/1997| Initial revision                                     ST
    1   |31/03/1997| First aminet release                                 ST
    2   |13/05/1997| Fixed bug in imdct_number                            ST
    3   |23/05/1997| Added MPEGDEC_ERR_xxx                                ST
    4   |27/05/1997| Added MPEGIMDCT                                      ST
    5   |05/06/1997| FPU Optimized version                                ST
    6   |07/06/1997| Use now BSTR_read_bytes & HUFF_fill_bytes            ST
    7   |08/07/1997| Optimized dequantization for INT arithmetic          ST
    8   |13/07/1997| Optimized mono_forced decoding                       ST
    9   |14/07/1997| Optimized stereo function with nul bands             ST
    10  |14/07/1997| Added MPEG3_get_nul_pos, optimized dequantization    ST
    11  |24/05/1999| Suppressed all static vars to allow multi-decoding   ST

    ------------------------------------------------------------------------

    MPEG layer III decoding functions

------------------------------------------------------------------------------*/

#include <stdio.h>

#include "defs.h"
#include "bitstr.h"
#include "mpegaud.h"
#include "mpegtab.h"

#include "mpegsub.h"
#include "mpegimdc.h" // #4

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM_2)
#ifdef MPEGAUD_INT
#include "mpegsubb.h"
#else
#include "mpegsubf.h" // #5
#endif
#endif

#include "mpegdec.h"
#include "mpeg3dec.h"
#include <math.h>

#ifdef USE_RC4
#include "rc4.h"
#endif

static int MPEG3_main_data_slots( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Return the main data slots of current MPEG III frame
*/
{
   INT32 slots;
   MPA_HEADER *h = &mps->header;


   slots = ( 144000 * mps->bitrate ) / mps->sfreq;

   if( h->ID == MPA_ID_1 ) { // MPEG1
      if( mps->stereo ) slots -= 36;
      else slots -= 21;
   } else { // MPEG2
      slots >>= 1;
      if( mps->stereo ) slots -= 21;
      else slots -= 13;
   }

   if( h->padding_bit ) slots++;
   if( h->protection_bit ) slots -= 2;
   return slots;

} /* MPEG3_main_data_slots */

static int MPEG3_decode_side_info( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the sideo info of MPEG III stream
   Return 0 if Ok
*/
{
   BITSTREAM *bs = mps->bitstream;
   MPA_SIDE_INFO *si = &mps->side_info;
   UINT16 ch, i, gr;
   UINT16 gr_max, scf;

   if( mps->header.ID == MPA_ID_1 ) { // MPEG1
      gr_max = MPA_MAX_GRANULES;
      scf = 4;
      si->main_data_begin = BSTR_read_bits( bs, 9 );
      if( mps->stereo ) si->private_bits = BSTR_read_bits( bs, 3 );
      else si->private_bits = BSTR_read_bits( bs, 5 );
      for( ch=0; ch<mps->channels; ch++ ) {
         for( i=0; i<4; i++ ) si->ch[ ch ].scfsi[ i ] = BSTR_read_bit( bs );
      }
   }
   else { // MPEG2 - LSF
      gr_max = 1;
      scf = 9;
      si->main_data_begin = BSTR_read_bits( bs, 8 );
      if( mps->stereo ) si->private_bits = BSTR_read_bits( bs, 2 );
      else si->private_bits = BSTR_read_bits( bs, 1 );
   }

MPEGAUD_CHECK_DEMO;

   for( gr=0; gr<gr_max; gr++ ) {
      for( ch=0; ch<mps->channels; ch++ ) {
         MPA_GRANULE_INFO *gi = &si->ch[ ch ].gr[ gr ];
         gi->part2_3_length    = BSTR_read_bits( bs, 12 );
         gi->big_values        = BSTR_read_bits( bs, 9 );
         gi->global_gain       = BSTR_read_bits( bs, 8 );
         gi->scalefac_compress = BSTR_read_bits( bs, scf );
         gi->window_switching_flag = BSTR_read_bit( bs );

#if 0
	 printf("gi->part2_3_length: %08x\n", gi->part2_3_length);
	 printf("gi->big_values: %08x\n", gi->big_values);
	 printf("gi->global_gain: %08x\n", gi->global_gain);
	 printf("gi->scalefac_compress: %08x\n", gi->scalefac_compress);
	 printf("gi->window_switching_flag: %08x\n", gi->window_switching_flag);
#endif

         if( gi->window_switching_flag ) {
            gi->block_type = BSTR_read_bits( bs, 2 );
            gi->mixed_block_flag = BSTR_read_bit( bs );
            for( i=0; i<2; i++ ) gi->table_select[ i ] = BSTR_read_bits( bs, 5 );
            for( i=0; i<3; i++ ) gi->subblock_gain[ i ] = BSTR_read_bits( bs, 3 );
            // Implicit regionX_count parameters setting
            if( (gi->block_type == 2) && (!gi->mixed_block_flag) ) gi->region0_count = 8;
            else gi->region0_count = 7;
            gi->region1_count = 20 - gi->region0_count;
         }
         else {
            for( i=0; i<3; i++ ) gi->table_select[ i ] = BSTR_read_bits( bs, 5 );
            gi->region0_count = BSTR_read_bits( bs, 4 );
            gi->region1_count = BSTR_read_bits( bs, 3 );
            gi->block_type = 0;
         }
         if( mps->header.ID == MPA_ID_1 ) gi->preflag = BSTR_read_bit( bs );
         gi->scalefac_scale = BSTR_read_bit( bs );
         gi->count1table_select = BSTR_read_bit( bs );
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_decode_side_info */

static const INT16 slen[ 2 ][ 16 ] = {
   {0, 0, 0, 0, 3, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4},
   {0, 1, 2, 3, 0, 1, 2, 3, 1, 2, 3, 1, 2, 3, 2, 3}
};

static int MPEG3_decode_scale1( MPA_STREAM *mps, INT16 gr, INT16 ch )
/*--------------------------------------------------------------------------
   Decode the scales of MPEG1-III stream
   Return 0 if Ok
*/
{
   INT16 sfb, win;
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ ch ].gr[ gr ];
   MPA_SCALE_FAC3 *sf = &mps->scale_fac3[ ch ];
   HUFFMAN *h = mps->huffman;
   INT16 slen1 = slen[ 0 ][ gi->scalefac_compress ];
   INT16 slen2 = slen[ 1 ][ gi->scalefac_compress ];

   if( (gi->window_switching_flag) && (gi->block_type == 2) ) {
      if( gi->mixed_block_flag ) { // Mixed block
         for( sfb=0; sfb<8; sfb++ ) sf->l[ sfb ] = HUFF_read_bits( h, slen1 );
         for( sfb=3; sfb<6; sfb++ )
            for( win=0; win<3; win++ ) sf->s[ win ][ sfb ] = HUFF_read_bits( h, slen1 );
         for( sfb=6; sfb<12; sfb++ )
            for( win=0; win<3; win++ ) sf->s[ win ][ sfb ] = HUFF_read_bits( h, slen2 );
         sf->s[ 0 ][ 12 ] = sf->s[ 1 ][ 12 ] = sf->s[ 2 ][ 12 ] = 0;
      }
      else { // Short blocks
         for( sfb=0; sfb<6; sfb++ )
            for( win=0; win<3; win++ ) sf->s[ win ][ sfb ] = HUFF_read_bits( h, slen1 );
         for( sfb=6; sfb<12; sfb++ )
            for( win=0; win<3; win++ ) sf->s[ win ][ sfb ] = HUFF_read_bits( h, slen2 );
         sf->s[ 0 ][ 12 ] = sf->s[ 1 ][ 12 ] = sf->s[ 2 ][ 12 ] = 0;
      }
   }
   else { // Long blocks 0, 1 or 3
      if( (mps->side_info.ch[ ch ].scfsi[ 0 ] == 0) || (gr == 0) ) {
         for( sfb = 0; sfb < 6; sfb++ ) sf->l[ sfb ] = HUFF_read_bits( h, slen1 );
      }
      if( (mps->side_info.ch[ ch ].scfsi[ 1 ] == 0) || (gr == 0) ) {
         for( sfb = 6; sfb < 11; sfb++ ) sf->l[ sfb ] = HUFF_read_bits( h, slen1 );
      }
      if( (mps->side_info.ch[ ch ].scfsi[ 2 ] == 0) || (gr == 0) ) {
         for( sfb = 11; sfb < 16; sfb++ ) sf->l[ sfb ] = HUFF_read_bits( h, slen2 );
      }
      if( (mps->side_info.ch[ ch ].scfsi[ 3 ] == 0) || (gr == 0) ) {
         for( sfb = 16; sfb < 21; sfb++ ) sf->l[ sfb ] = HUFF_read_bits( h, slen2 );
      }
      sf->l[ 21 ] = sf->l[ 22 ] = 0;
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_decode_scale1 */

static const INT16 sfb_bt[ 6 ][ 3 ][ 4 ] = {
   { {6,  5,  5, 5}, {9,  9,  9,  9}, {6,  9,  9,  9} },
   { {6,  5,  7, 3}, {9,  9,  12, 6}, {6,  9,  12, 6} },
   { {11, 10, 0, 0}, {18, 18, 0,  0}, {15, 18, 0,  0} },
   { {7,  7,  7, 0}, {12, 12, 12, 0}, {6,  15, 12, 0} },
   { {6,  6,  6, 3}, {12, 9,  9,  6}, {6,  12, 9,  6} },
   { {8,  8,  5, 0}, {15, 12, 9,  0}, {6,  18, 9,  0} }
};

static int MPEG3_decode_scale2( MPA_STREAM *mps, INT16 gr, INT16 ch )
/*--------------------------------------------------------------------------
   Decode the scales of MPEG2-III stream
   Return 0 if Ok
*/
{
   INT16 i, j, k, sfb, win;
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ ch ].gr[ gr ];
   MPA_SCALE_FAC3 *sf = &mps->scale_fac3[ ch ];
   HUFFMAN *h = mps->huffman;
   INT16 block_type_number, block_number;
   INT16 slen[ 4 ];
   INT16 sfb_nb, len;
   INT16 scalefac[ 36 ]; /* #11 suppressed static */
   INT16 is_max[ 36 ]; /* #11 suppressed static */
//memset( sf, 0, sizeof( MPA_SCALE_FAC3 ) );
   block_type_number = 0;
   if( gi->block_type == 2 ) block_type_number = (gi->mixed_block_flag)?2:1;

MPEGAUD_CHECK_DEMO;

   if( ( (mps->header.mode_extension == 1) || (mps->header.mode_extension == 3) ) &&
       ( ch == 1 ) ) {
      INT16 int_scalefac_comp = gi->scalefac_compress >> 1;

      if( int_scalefac_comp < 180 ) {
         slen[ 0 ] = int_scalefac_comp  / 36 ;
         slen[ 1 ] = (INT16)(int_scalefac_comp % 36) / 6;
         slen[ 2 ] = (INT16)(int_scalefac_comp % 36) % 6;
         slen[ 3 ] = 0;
         gi->preflag = 0;
         block_number = 3;
      }
      else if( int_scalefac_comp < 244 ) {
         slen[ 0 ] = ((INT16)(int_scalefac_comp - 180) % 64) >> 4;
         slen[ 1 ] = ((INT16)(int_scalefac_comp - 180) % 16) >> 2;
         slen[ 2 ] =  (INT16)(int_scalefac_comp - 180) % 4;
         slen[ 3 ] = 0;
         gi->preflag = 0;
         block_number = 4;
      }
      else {
         slen[ 0 ] = (INT16)(int_scalefac_comp - 244) / 3;
         slen[ 1 ] = (INT16)(int_scalefac_comp - 244) % 3;
         slen[ 2 ] = 0 ;
         slen[ 3 ] = 0;
         gi->preflag = 0;
         block_number = 5;
      }
   }
   else {
      INT16 scalefac_comp = gi->scalefac_compress;

      if( scalefac_comp < 400 ) {
         slen[ 0 ] = (INT16)(scalefac_comp >> 4) / 5;
         slen[ 1 ] = (INT16)(scalefac_comp >> 4) % 5;
         slen[ 2 ] = (INT16)(scalefac_comp % 16) >> 2;
         slen[ 3 ] = (INT16)(scalefac_comp % 4);
         gi->preflag = 0;
         block_number = 0;
      }
      else if( scalefac_comp  < 500 ) {
         slen[ 0 ] = ((INT16)(scalefac_comp - 400) >> 2) / 5;
         slen[ 1 ] = ((INT16)(scalefac_comp - 400) >> 2) % 5;
         slen[ 2 ] =  (INT16)(scalefac_comp - 400) % 4;
         slen[ 3 ] = 0;
         gi->preflag = 0;
         block_number = 1;
      }
      else {
         slen[ 0 ] = (INT16)(scalefac_comp - 500) / 3;
         slen[ 1 ] = (INT16)(scalefac_comp - 500) % 3;
         slen[ 2 ] = 0;
         slen[ 3 ] = 0;
         gi->preflag = 1;
         block_number = 2;
      }
   }

   k = 0;
   for( i=0; i<4; i++ ) {
      sfb_nb = sfb_bt[ block_number ][ block_type_number ][ i ];
      len = slen[ i ];
      if( len ) {
         for( j=0; j<sfb_nb; j++ ) {
            scalefac[ k ] = HUFF_read_bits( h, len );
            is_max[ k++ ] = (1<<len) - 1;
         }
      }
      else {
         for( j=0; j<sfb_nb; j++ ) {
            scalefac[ k ] = 0;
            is_max[ k++ ] = 0;
         }
      }
   }
   while( k < 36 ) scalefac[ k++ ] = 0;

   k = 0;

MPEGAUD_CHECK_DEMO;

   if( (gi->window_switching_flag) && (gi->block_type == 2) ) {
      if( gi->mixed_block_flag ) { // Mixed block
// *** WARNING
// *** WARNING  sfb<8 seems to be inexact, sfb<6 seems to be ok (? NO, conform to ISO/IEC)
// *** WARNING
         for( sfb=0; sfb<6; sfb++ ) {
            sf->l[ sfb ] = scalefac[ k ];
            mps->is_max_l[ sfb ] = is_max[ k++ ];
         }
         for( sfb=3; sfb<12; sfb++ ) {
            for( win=0; win<3; win++ ) {
               sf->s[ win ][ sfb ] = scalefac[ k ];
               mps->is_max_s[ win ][ sfb ] = is_max[ k++ ];
            }
         }
         sf->s[ 0 ][ 12 ] = sf->s[ 1 ][ 12 ] = sf->s[ 2 ][ 12 ] = 0;
      }
      else { // Short blocks
         for( sfb=0; sfb<12; sfb++ ) {
            for( win=0; win<3; win++ ) {
               sf->s[ win ][ sfb ] = scalefac[ k ];
               mps->is_max_s[ win ][ sfb ] = is_max[ k++ ];
            }
         }
         sf->s[ 0 ][ 12 ] = sf->s[ 1 ][ 12 ] = sf->s[ 2 ][ 12 ] = 0;
      }
   }
   else { // Long blocks 0, 1 or 3
      for( sfb=0; sfb<21; sfb++ ) {
         sf->l[ sfb ] = scalefac[ k ];
         mps->is_max_l[ sfb ] = is_max[ k++ ];
      }
      sf->l[ 21 ] = sf->l[ 22 ] = 0;
   }
   return MPEGDEC_ERR_NONE;

} /* MPEG3_decode_scale2 */

// Note: où sont utilisées  sf->s[ w ][ 12 ]...
// et  sf->l[ 21 ] = sf->l[ 22 ] ?

static const INT16 sfBandIndex_l[ 2 ][ 3 ][ 23 ] = {
  { {0,6,12,18,24,30,36,44,54,66,80,96,116,140,168,200,238,284,336,396,464,522,576},
    {0,6,12,18,24,30,36,44,54,66,80,96,114,136,162,194,232,278,330,394,464,540,576},
    {0,6,12,18,24,30,36,44,54,66,80,96,116,140,168,200,238,284,336,396,464,522,576} },
  { {0,4,8,12,16,20,24,30,36,44,52,62,74,90,110,134,162,196,238,288,342,418,576},
    {0,4,8,12,16,20,24,30,36,42,50,60,72,88,106,128,156,190,230,276,330,384,576},
    {0,4,8,12,16,20,24,30,36,44,54,66,82,102,126,156,194,240,296,364,448,550,576} }
};

static const INT16 sfBandIndex_s[ 2 ][ 3 ][ 14 ] = {
  { {0,4,8,12,18,24,32,42,56,74,100,132,174,192},
    {0,4,8,12,18,26,36,48,62,80,104,136,180,192},
    {0,4,8,12,18,26,36,48,62,80,104,134,174,192} },
  { {0,4,8,12,16,22,30,40,52,66,84,106,136,192},
    {0,4,8,12,16,22,28,38,50,64,80,100,126,192},
    {0,4,8,12,16,22,30,42,58,78,104,138,180,192} }
};


static int MPEG3_huffman_decode( MPA_STREAM *mps, INT16 *is,
                                 INT16 gr, INT16 ch, int part2_start )
/*--------------------------------------------------------------------------
   Decode the huffman data of MPEG III stream
   Return 0 if Ok
*/
{
   INT16 i;
   INT16 region1Start;
   INT16 region2Start;
   INT16 region_stop;
   INT16 *isp;
   INT16 htable;
   INT16 huff_count;
   INT16 max_val;
   int pos, count;
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ ch ].gr[ gr ];
   HUFFMAN *h = mps->huffman;

   if( (gi->window_switching_flag) && (gi->block_type == 2) ) {
      region1Start = 36;  // sfb[9/3]*3=36
      region2Start = 576; // No Region2 for short block case
   }
   else {
      const INT16 *band = sfBandIndex_l[ mps->header.ID ][ mps->header.sampling_frequency ];

      region1Start = band[ gi->region0_count + 1 ];
      region2Start = band[ gi->region0_count + gi->region1_count + 2 ];
   }

MPEGAUD_CHECK_DEMO;

   /* Read bigvalues area. */
   i = 0;
   isp = is;
   region_stop = (gi->big_values) << 1;

   max_val = mps->sb_max * MPA_SSLIMIT;
   if( max_val > 574 ) max_val = 574;
   if( region_stop > max_val ) region_stop = max_val;

   if( region1Start > region_stop ) region1Start = region_stop;
   if( region2Start > region_stop ) region2Start = region_stop;


   if( region_stop > 0 ) {
      huff_count = region1Start-i;
      if( huff_count > 0 ) {
         HUFF_decode_pair( h, gi->table_select[ 0 ], (INT16)(huff_count>>1), isp );
         isp += huff_count;
         i += huff_count;
      }
      huff_count = region2Start-i;
      if( huff_count > 0 ) {
         HUFF_decode_pair( h, gi->table_select[ 1 ], (INT16)(huff_count>>1), isp );
         isp += huff_count;
         i += huff_count;
      }
      huff_count = region_stop-i;
      if( huff_count > 0 ) {
         HUFF_decode_pair( h, gi->table_select[ 2 ], (INT16)(huff_count>>1), isp );
         isp += huff_count;
         i += huff_count;
      }
   }
   /* Read count1 area. */
   htable = gi->count1table_select;
   pos = HUFF_pos( h );
   count = HUFF_diff( part2_start, pos ); // bits already used
   region_stop = gi->part2_3_length - count; // max bits to use
   HUFF_decode_quad( h, htable, region_stop, i, max_val, isp );

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_huffman_decode */


// #10 Begin
static INT16 MPEG3_get_nul_pos( MPA_STREAM *mps, INT16 *is, INT16 gr, INT16 ch )
/*--------------------------------------------------------------------------
   Get nul pos of the current samples of MPEG III stream
   Return 0 if Ok
*/
{
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ ch ].gr[ gr ];
   const INT16 *band_l = sfBandIndex_l[ mps->header.ID ][ mps->header.sampling_frequency ];
   const INT16 *band_s = sfBandIndex_s[ mps->header.ID ][ mps->header.sampling_frequency ];
   INT16 nul_begin = mps->huffman->nul_begin; // = big_value*2 + count1*4 (normaly)
   INT16 sfb;

   if( (gi->window_switching_flag) && (gi->block_type == 2) ) { // Short blocks
      INT16 nul_s;

      nul_s = (INT16)(nul_begin + 2) / 3;
      if( gi->mixed_block_flag ) { // First 2 subbands are long blocks
         if( nul_begin > 36 ) { // can be in short blocks
            sfb = 12;
            while( (band_s[ sfb ] >= nul_s) && (sfb >= 3) ) sfb--;
            mps->sfb_nul_s_top[ ch ] = mps->sfb_nul_s[ 0 ][ ch ] =
            mps->sfb_nul_s[ 1 ][ ch ] = mps->sfb_nul_s[ 2 ][ ch ] = sfb+1;
            mps->sfb_nul_l[ ch ] = 8;
         }
         else {
            sfb = 7;
            while( (band_l[ sfb ] >= nul_begin) && (sfb >= 0) ) sfb--;
            mps->sfb_nul_l[ ch ] = sfb+1;
            mps->sfb_nul_s_top[ ch ] = mps->sfb_nul_s[ 0 ][ ch ] =
            mps->sfb_nul_s[ 1 ][ ch ] = mps->sfb_nul_s[ 2 ][ ch ] = 3;
         }
      }
      else {
         sfb = 12;
         while( (band_s[ sfb ] >= nul_s) && (sfb >= 0) ) sfb--;
         mps->sfb_nul_s_top[ ch ] = mps->sfb_nul_s[ 0 ][ ch ] =
         mps->sfb_nul_s[ 1 ][ ch ] = mps->sfb_nul_s[ 2 ][ ch ] = sfb+1;
         mps->sfb_nul_l[ ch ] = 0;
      }
      if( mps->header.ID == MPA_ID_2 ) { // Each null band should be evaluated for each window
         INT16 w;
         INT16 sfb_top = mps->sfb_nul_s[ 0 ][ ch ];
         INT16 sfb_min = (gi->mixed_block_flag) ? 3 : 0;

         mps->sfb_nul_s_top[ ch ] = 0;
         for( w=0; w<3; w++ ) {
            register INT16 index;
            register INT16 cnt;
            register INT16 *isp;

            sfb = sfb_top;
            index = (band_s[ sfb-1 ]*3) + ((INT16)(band_s[ sfb ]-band_s[ sfb-1 ])*(INT16)(w+1)) -1;
            if( nul_begin < index ) index = nul_begin;
            while( sfb > sfb_min ) {
               isp = &is[ index ];
               cnt = 1 + index - ((band_s[ sfb-1 ]*3) + ((INT16)(band_s[ sfb ]-band_s[ sfb-1 ])*w) );
               while( cnt-- ) if( *isp-- ) break;
               if( cnt >= 0 ) break;
               sfb--;
               index = (band_s[ sfb-1 ]*3) + ((INT16)(band_s[ sfb ]-band_s[ sfb-1 ])*(INT16)(w+1)) -1;
            }
            mps->sfb_nul_s[ w ][ ch ] = sfb;
            if( sfb > mps->sfb_nul_s_top[ ch ] ) mps->sfb_nul_s_top[ ch ] = sfb;
            if( (sfb == sfb_min) && (sfb_min > 0) ) { // Find into long blocks now
               sfb = 6;
               index = band_l[ sfb ]-1;
               if( nul_begin < index ) index = nul_begin;
               while( sfb > 0 ) {
                  isp = &is[ index ];
                  cnt = 1 + index - band_l[ sfb-1 ];
                  while( cnt-- ) if( *isp-- ) break;
                  if( cnt >= 0 ) break;
                  sfb--;
                  index = band_l[ sfb ]-1;
               }
               mps->sfb_nul_l[ ch ] = sfb;
            }
         }

      }
   }
   else { // Long Blocks
      sfb = 21;
      while( (band_l[ sfb ] >= nul_begin) && (sfb >= 0) ) sfb--;
      mps->sfb_nul_l[ ch ] = sfb+1;
      mps->sfb_nul_s[ 0 ][ ch ] = mps->sfb_nul_s[ 1 ][ ch ] = mps->sfb_nul_s[ 2 ][ ch ]  = 0;
      mps->sfb_nul_s_top[ ch ] = 0;
   }
   if( (mps->header.mode == MPA_MODE_JOINT_STEREO) && (ch > 0) ) {
      mps->imdct_max[ 1 ] = mps->imdct_max[ 0 ];
   }
   else {
      mps->imdct_max[ ch ] = 1 + (INT16)(nul_begin + (MPA_SSLIMIT-1)) / MPA_SSLIMIT;
      if( mps->imdct_max[ ch ] > mps->sb_max ) mps->imdct_max[ ch ] = mps->sb_max;
      if( mps->imdct_max[ ch ] > MPA_SBLIMIT ) mps->imdct_max[ ch ] = MPA_SBLIMIT;
   }

   return MPEGDEC_ERR_NONE;

} /* MPEG3_get_nul_pos */
// #10 End


static const INT16 pretab[ 22 ] = {0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,2,2,3,3,3,2,0};

#ifdef MPEGAUD_INT
#define POW_TYPE INT32
#define POW_2_BITS 13
#define POW_4_3_BITS MPEGTAB_POW_BITS // 18 usually
#else
#define POW_TYPE REAL
#endif

static INT16 MPEG3_dequantize_samples( MPA_STREAM *mps, INT16 *is,
                                       MPEGAUD_FRACT_TYPE *xr,
                                       INT16 gr, INT16 ch )
/*--------------------------------------------------------------------------
   Dequantize the current samples of MPEG III stream
   Return 0 if Ok
*/
{
   static BOOL init = FALSE;
#ifdef MPEGAUD_INT
   static POW_TYPE pow_2[ 4 ] = { 8192, 4870, 5792, 6888 }; // Init for POW_2_BITS = 13 (rounded to lowest)
   INT16 sh, xrk_sh;
   POW_TYPE *pow4; // #7
#ifdef SPLIT_TABLE
   static POW_TYPE *pow_4_3_t[4];
#endif
#else
   static POW_TYPE *pows = NULL;
   static POW_TYPE *pow_2;
   #define POW_2_MAX   434 // 178+255+1
#endif

   static POW_TYPE *pow_4_3 = NULL;
   #define POW_4_3_MAX 8192

   //   static FILE *fquant;

   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ ch ].gr[ gr ];
   MPA_SCALE_FAC3 *scf = &mps->scale_fac3[ ch ];
   const INT16 *band_l = sfBandIndex_l[ mps->header.ID ][ mps->header.sampling_frequency ];
   const INT16 *band_s = sfBandIndex_s[ mps->header.ID ][ mps->header.sampling_frequency ];
   INT16 sfb;
   INT16 k, window;
   INT16 gk;
   register MPEGAUD_FRACT_TYPE *xrp;
   register INT16 *isp;
   register POW_TYPE xrk;

#ifdef MPEGAUD_INT
// #7 Begin
#if 1
#define DEQ( sa ) if( sa >= 0 ) {\
                     sh = xrk_sh + (MPT_pow_4_3[ sa ] & 0xFF);\
                     if( sh < 32 ) *xrp = pow4[ sa ]>>sh;\
                     else *xrp = 0;\
                  }\
                  else {\
                     sh = xrk_sh + (MPT_pow_4_3[ -(sa) ] & 0xFF);\
                     if( sh < 32 ) *xrp = -(pow4[ -(sa) ]>>sh);\
                     else *xrp = 0;\
                  } \
//                 fprintf(fquant, "sa: %08x, xrk_sh: %08x, sh: %03x, xrp: %02x\n", sa, xrk_sh, sh, *xrp);
#else
   register INT32 pow_4_3_val;
#define DEQ( sa ) if( sa >= 0 ) {\
                     pow_4_3_val = pow_4_3[ sa ];\
                     sh = xrk_sh + (pow_4_3_val & 0xFF);\
                     if( sh < 32 ) *xrp = (xrk * (pow_4_3_val>>8))>>sh;\
                     else *xrp = 0;\
                  }\
                  else {\
                     pow_4_3_val = pow_4_3[ -(sa) ];\
                     sh = xrk_sh + (pow_4_3_val & 0xFF);\
                     if( sh < 32 ) *xrp = -((xrk * (pow_4_3_val>>8))>>sh);\
                     else *xrp = 0;\
                  }
#endif
#else
// #7 End
#define DEQ( sa ) if( sa >= 0 ) {\
                     *xrp = xrk * pow_4_3[ sa ];\
                  }\
                  else {\
                     *xrp = -xrk * pow_4_3[ -(sa) ];\
                  }
#endif

   if( !init ) {
      register INT16 i;
#ifdef MPEGAUD_INT
      // Pre calc 2^(1/4 * k) * 2^POW2_BITS
      // ie: Keep POW_2_BITS as mantissa
      // #7 Begin

#ifdef SPLIT_TABLE
      pow_4_3_t[0] = (POW_TYPE *)malloc( (POW_4_3_MAX * sizeof(POW_TYPE)));
      if( !pow_4_3_t[0] ) return MPEGDEC_ERR_MEM;
      pow_4_3_t[1] = (POW_TYPE *)malloc( (POW_4_3_MAX * sizeof(POW_TYPE)));
      if( !pow_4_3_t[1] ) return MPEGDEC_ERR_MEM;
      pow_4_3_t[2] = (POW_TYPE *)malloc( (POW_4_3_MAX * sizeof(POW_TYPE)));
      if( !pow_4_3_t[2] ) return MPEGDEC_ERR_MEM;
      pow_4_3_t[3] = (POW_TYPE *)malloc( (POW_4_3_MAX * sizeof(POW_TYPE)));
      if( !pow_4_3_t[3] ) return MPEGDEC_ERR_MEM;

      for( k=0; k<4; k++ ) {
         pow4 = pow_4_3_t[ k ];
         xrk = pow_2[ k ];
         for( i=0; i<POW_4_3_MAX; i++ ) {
            pow4[ i ] = xrk * (MPT_pow_4_3[ i ]>>8);
         }
      }
#else

      pow_4_3 = (POW_TYPE *)malloc( (POW_4_3_MAX * 4 * sizeof(POW_TYPE)) - 1);
      if( !pow_4_3 ) return MPEGDEC_ERR_MEM;
      for( k=0; k<4; k++ ) {
         pow4 = &pow_4_3[ k*POW_4_3_MAX ];
         xrk = pow_2[ k ];
         for( i=0; i<POW_4_3_MAX; i++ ) {
            pow4[ i ] = xrk * (MPT_pow_4_3[ i ]>>8);
         }
      }
#endif

//    pow_4_3 = (POW_TYPE *)MPT_pow_4_3;
      // #7 End
#if 0
      printf("power tables\n");
      for( i=0; i<4; i++ ) 
	printf("pow_2[%d]: %d\n", i, pow_2[i]);
      for( i=0; i<16; i++ )
#ifdef SPLIT_TABLE
        printf("pow_4_3_t[0][%d]: %x\n", i, *(pow_4_3_t[0] + i)); 
#else
        printf("pow_4_3[%d]: %x\n", i, pow_4_3[ i ]); 
#endif
#endif
#else
      pows = (POW_TYPE *)malloc( (POW_2_MAX + POW_4_3_MAX) * sizeof(POW_TYPE) );
      if( !pows ) return MPEGDEC_ERR_MEM;
      pow_2 = pows;
      pow_4_3 = pow_2 + POW_2_MAX;
      for( i=0; i<POW_2_MAX; i++ ) pow_2[ i ] = pow( 2.0, 0.25 * (double)(i - 388) );
      for( i=0; i<POW_4_3_MAX; i++ ) pow_4_3[ i ] = pow( (double)i, 4.0/3.0 );
#if 0
      printf("power tables\n");
      for( i=0; i<POW_2_MAX; i++ ) 
	printf("pow_2[%d]: %08x\n", i, pow_2[i]);
      for( i=0; i<POW_4_3_MAX; i++ )
        printf("pow_4_3[%d]: %08x\n", i, pow_4_3[ i ]); 
#endif
#endif
      //      fquant = fopen("quant.out", "w");
      init = TRUE;
   }

   isp = is;
   xrp = xr;
   gk = gi->global_gain + 178;

MPEGAUD_CHECK_DEMO;

   if( (gi->window_switching_flag) && (gi->block_type == 2) ) { // Short blocks
      sfb = 0;
      if( gi->mixed_block_flag ) { // First 2 subbands are long blocks
         while( band_l[ sfb+1 ] < 36 ) {
            register INT16 i = band_l[ sfb+1 ] - band_l[ sfb ];
            k = scf->l[ sfb ];
            if( gi->preflag ) k += pretab[ sfb ];
            if( gi->scalefac_scale ) k <<= 1;
#ifdef MPEGAUD_INT
            // #7 Begin
//            xrk = pow_2[ (gk - (k<<1)) & 3 ];
#ifdef SPLIT_TABLE
            pow4 = pow_4_3_t[ ((gk - (k<<1)) & 3)];
#else
            pow4 = &pow_4_3[ ((gk - (k<<1)) & 3) * POW_4_3_MAX ];
#endif
            xrk_sh = POW_2_BITS-MPEGAUD_FRACT_BITS - ((gk - (k<<1)-388+3)>>2);
            // #7 End
#else
            xrk = pow_2[ gk - (k<<1) ];
#endif
            while( i-- ) {
               if( *isp ) {
                  DEQ( *isp );
                  xrp++;
               }
               else *xrp++ = (MPEGAUD_FRACT_TYPE)0;
               isp++;
            }
            sfb++;
         }
         sfb = 3; // Start of short blocks now
      }
      // Short part
//      while( sfb<13 ) {
      while( sfb<mps->sfb_nul_s_top[ ch ] ) {
         for( window=0; window<3; window++ ) {
            register INT16 i = band_s[ sfb+1 ] - band_s[ sfb ];
            k = scf->s[ window ][ sfb ];
            if( gi->scalefac_scale ) k <<= 1;
            k += (gi->subblock_gain[ window ] << 2);
#ifdef MPEGAUD_INT
            // #7 Begin
//            xrk = pow_2[ (gk - (k<<1)) & 3 ];
#ifdef SPLIT_TABLE
            pow4 = pow_4_3_t[ ((gk - (k<<1)) & 3) ];
#else
            pow4 = &pow_4_3[ ((gk - (k<<1)) & 3) * POW_4_3_MAX ];
#endif
            xrk_sh = POW_2_BITS-MPEGAUD_FRACT_BITS - ((gk - (k<<1)-388+3)>>2);
            // #7 End
#else
            xrk = pow_2[ gk - (k<<1) ];
#endif
            while( i-- ) {
               if( *isp ) {
                  DEQ( *isp );
                  xrp++;
               }
               else *xrp++ = (MPEGAUD_FRACT_TYPE)0;
               isp++;
            }
         }
         sfb++;
      }

      {
         register INT16 i = MPA_GRANULE_SIZE - (band_s[ sfb ]*3);
         if( i > 0 ) {
            while( i-- ) *xrp++ = (MPEGAUD_FRACT_TYPE)0;
         }
      }
   }
   else { // Long blocks
//      for( sfb=0; sfb<22; sfb++ ) {
      for( sfb=0; sfb<mps->sfb_nul_l[ ch ]; sfb++ ) {
         register INT16 i = band_l[ sfb+1 ] - band_l[ sfb ];
         k = scf->l[ sfb ];
         if( gi->preflag ) k += pretab[ sfb ];
         if( gi->scalefac_scale ) k <<= 1;
#ifdef MPEGAUD_INT
         // #7 Begin
//         xrk = pow_2[ (gk - (k<<1)) & 3 ];
#ifdef SPLIT_TABLE
         pow4 = pow_4_3_t[ ((gk - (k<<1)) & 3)];
#else
         pow4 = &pow_4_3[ ((gk - (k<<1)) & 3) * POW_4_3_MAX ];
#endif
         xrk_sh = POW_2_BITS-MPEGAUD_FRACT_BITS - ((gk - (k<<1)-388+3)>>2);
         // #7 End
#else
         xrk = pow_2[ gk - (k<<1) ];
#endif
         while( i-- ) {
            if( *isp ) {
               DEQ( *isp );
               xrp++;
            }
            else *xrp++ = (MPEGAUD_FRACT_TYPE)0;
            isp++;
         }
      }

      {
         register INT16 i = MPA_GRANULE_SIZE - band_l[ sfb ];
         if( i > 0 ) {
            while( i-- ) *xrp++ = (MPEGAUD_FRACT_TYPE)0;
         }
      }
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_dequantize_samples */


#define MAX_POS1 7
#define MAX_POS2 32

#ifdef MPEGAUD_INT
// #9 INT32 -> INT16 for ST_TYPE
#define ST_TYPE INT16
#define ST_BITS 14
#define ST_MULT( a, b ) (((ST_TYPE)(a) * (ST_TYPE)(b))>>ST_BITS)
// Precalc tables for ST_BITS = 14
static const ST_TYPE tan_pos0[ MAX_POS1 ] = {
   0x0000, 0x0D86, 0x176C, 0x2000, 0x2893, 0x3279, 0x4000
};
static const ST_TYPE tan_pos1[ MAX_POS1 ] = {
   0x4000, 0x3279, 0x2893, 0x2000, 0x176C, 0x0D86, 0x0000
};
static const ST_TYPE pow_io0[ 2 ][ MAX_POS2 ] = {
   0x4000, 0x35D1, 0x4000, 0x2D41, 0x4000, 0x260D, 0x4000, 0x2000,
   0x4000, 0x1AE8, 0x4000, 0x16A0, 0x4000, 0x1306, 0x4000, 0x1000,
   0x4000, 0x0D74, 0x4000, 0x0B50, 0x4000, 0x0983, 0x4000, 0x0800,
   0x4000, 0x06BA, 0x4000, 0x05A8, 0x4000, 0x04C1, 0x4000, 0x0400,
   0x4000, 0x2D41, 0x4000, 0x2000, 0x4000, 0x16A0, 0x4000, 0x1000,
   0x4000, 0x0B50, 0x4000, 0x0800, 0x4000, 0x05A8, 0x4000, 0x0400,
   0x4000, 0x02D4, 0x4000, 0x0200, 0x4000, 0x016A, 0x4000, 0x0100,
   0x4000, 0x00B5, 0x4000, 0x0080, 0x4000, 0x005A, 0x4000, 0x0040
};
static const ST_TYPE pow_io1[ 2 ][ MAX_POS2 ] = {
   0x4000, 0x4000, 0x35D1, 0x4000, 0x2D41, 0x4000, 0x260D, 0x4000,
   0x2000, 0x4000, 0x1AE8, 0x4000, 0x16A0, 0x4000, 0x1306, 0x4000,
   0x1000, 0x4000, 0x0D74, 0x4000, 0x0B50, 0x4000, 0x0983, 0x4000,
   0x0800, 0x4000, 0x06BA, 0x4000, 0x05A8, 0x4000, 0x04C1, 0x4000,
   0x4000, 0x4000, 0x2D41, 0x4000, 0x2000, 0x4000, 0x16A0, 0x4000,
   0x1000, 0x4000, 0x0B50, 0x4000, 0x0800, 0x4000, 0x05A8, 0x4000,
   0x0400, 0x4000, 0x02D4, 0x4000, 0x0200, 0x4000, 0x016A, 0x4000,
   0x0100, 0x4000, 0x00B5, 0x4000, 0x0080, 0x4000, 0x005A, 0x4000
};
#else
#define ST_TYPE REAL
#define ST_MULT( a, b ) ((a) * (b))
static const ST_TYPE tan_pos0[ MAX_POS1 ] = {
   0.0, 0.211324841, 0.366025358, 0.5, 0.633974493, 0.788674951, 1.0
};
static const ST_TYPE tan_pos1[ MAX_POS1 ] = {
   1.0, 0.788674951, 0.633974493, 0.5, 0.366025358, 0.211324841, 0.0
};
static const ST_TYPE pow_io0[ 2 ][ MAX_POS2 ] = {
   1.0, 0.840896368, 1.0, 0.707106769, 1.0, 0.594603539, 1.0, 0.500000000,
   1.0, 0.420448184, 1.0, 0.353553385, 1.0, 0.297301769, 1.0, 0.250000000,
   1.0, 0.210224092, 1.0, 0.176776692, 1.0, 0.148650885, 1.0, 0.125000000,
   1.0, 0.105112046, 1.0, 0.088388346, 1.0, 0.074325442, 1.0, 0.062500000,
   1.0, 0.707106769, 1.0, 0.500000000, 1.0, 0.353553385, 1.0, 0.250000000,
   1.0, 0.176776692, 1.0, 0.125000000, 1.0, 0.088388346, 1.0, 0.062500000,
   1.0, 0.044194173, 1.0, 0.031250000, 1.0, 0.022097087, 1.0, 0.015625000,
   1.0, 0.011048543, 1.0, 0.007812500, 1.0, 0.005524272, 1.0, 0.003906250,
};
static const ST_TYPE pow_io1[ 2 ][ MAX_POS2 ] = {
   1.0,         1.0, 0.840896368, 1.0, 0.707106769, 1.0, 0.594603539, 1.0,
   0.500000000, 1.0, 0.420448184, 1.0, 0.353553385, 1.0, 0.297301769, 1.0,
   0.250000000, 1.0, 0.210224092, 1.0, 0.176776692, 1.0, 0.148650885, 1.0,
   0.125000000, 1.0, 0.105112046, 1.0, 0.088388346, 1.0, 0.074325442, 1.0,
   1.0,         1.0, 0.707106769, 1.0, 0.500000000, 1.0, 0.353553385, 1.0,
   0.250000000, 1.0, 0.176776692, 1.0, 0.125000000, 1.0, 0.088388346, 1.0,
   0.062500000, 1.0, 0.044194173, 1.0, 0.031250000, 1.0, 0.022097087, 1.0,
   0.015625000, 1.0, 0.011048543, 1.0, 0.007812500, 1.0, 0.005524272, 1.0,
};
#endif

static int MPEG3_stereo( MPA_STREAM *mps, MPEGAUD_FRACT_TYPE *xr, INT16 gr )
/*--------------------------------------------------------------------------
   Decode the stereo data of a granule
   Return 0 if Ok
*/
{
  static int init = 0;
  static FILE *fquant;

   const INT16 *band_l = sfBandIndex_l[ mps->header.ID ][ mps->header.sampling_frequency ];
   const INT16 *band_s = sfBandIndex_s[ mps->header.ID ][ mps->header.sampling_frequency ];
   MPA_SCALE_FAC3 *sf = &mps->scale_fac3[ 1 ];
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ 0 ].gr[ gr ];

   BOOL ms_stereo = (mps->header.mode == MPA_MODE_JOINT_STEREO) &&
                    (mps->header.mode_extension & 0x2);
   BOOL i_stereo = (mps->header.mode == MPA_MODE_JOINT_STEREO) &&
                   (mps->header.mode_extension & 0x1);

   INT16 sfb;
   INT16 i, j, sb, sbmax; // #9: sbmax

   BOOL lsf = (mps->header.ID == MPA_ID_2);

   #define MAX_POS1 7
   #define MAX_POS2 32

   const ST_TYPE *pow_iok0;
   const ST_TYPE *pow_iok1;
   register MPEGAUD_FRACT_TYPE *xrp0, *xrp1, temp;
#ifdef MPEGAUD_INT
   register ST_TYPE sq2 = 0.7071067812 * (1<<ST_BITS);
#else
   register REAL sq2 = 0.7071067812;
#endif

   
   if( lsf ) {
      if( gi->scalefac_compress & 1 ) {
         pow_iok0 = pow_io0[ 1 ]; pow_iok1 = pow_io1[ 1 ];
      }
      else {
         pow_iok0 = pow_io0[ 0 ]; pow_iok1 = pow_io1[ 0 ];
      }
   }
   else {
      pow_iok0 = tan_pos0; pow_iok1 = tan_pos1;
   }

MPEGAUD_CHECK_DEMO;

   if( (mps->stereo) && i_stereo ) {
      ST_TYPE k0, k1;
      INT16 sfb_top;
      INT16 max_sfb = 0;
      INT16 ispos;
      INT16 is_illegal;

      if( gi->window_switching_flag && (gi->block_type == 2) ) {
         // #9 Begin
         sbmax = mps->sfb_nul_s_top[ 0 ];
         if( sbmax < mps->sfb_nul_s_top[ 1 ] ) sbmax = mps->sfb_nul_s_top[ 1 ];
         sbmax++;
         if( sbmax > 13 ) sbmax = 13;
         // #9 End

         for( j=0; j<3; j++ ) {
            sfb_top = mps->sfb_nul_s[ j ][ 1 ];
            if( (gi->mixed_block_flag) && (sfb_top < 3) ) sfb_top = 3; // Normaly not !!!
            if( sfb_top > max_sfb ) max_sfb = sfb_top;

            is_illegal = (lsf)?mps->is_max_s[ j ][ 0 ]:7;
            // Implicit: ispos == is_illegal here (not nul bands)
            ispos = is_illegal;
            for( sfb=0; sfb<sfb_top; sfb++ ) {
               sb = band_s[ sfb+1 ] - band_s[ sfb ];

               i = 3 * band_s[ sfb ] + j * sb;
               xrp0 = &xr[ i ]; xrp1 = &xr[ MPA_GRANULE_SIZE + i ];

               if( ms_stereo ) while( sb-- ) {
                  temp = ST_MULT( (*xrp0 + *xrp1), sq2 );
                  *xrp1 = ST_MULT( (*xrp0 - *xrp1), sq2 );
                  *xrp0++ = temp; xrp1++;
               }
            }
            while( sfb < sbmax ) { // #9: sbmax instead of 13
               sb = band_s[ sfb+1 ] - band_s[ sfb ];

               i = 3 * band_s[ sfb ] + j * sb;
               xrp0 = &xr[ i ]; xrp1 = &xr[ MPA_GRANULE_SIZE + i ];

               if( sfb < 12 ) {
                  ispos = sf->s[ j ][ sfb ]; // keep previous ispos for last sfb
                  is_illegal = (lsf)?mps->is_max_s[ j ][ sfb ]:7;
               }
               if( ispos == is_illegal ) {
                  if( ms_stereo ) while( sb-- ) {
                     temp = ST_MULT( (*xrp0 + *xrp1), sq2 );
                     *xrp1 = ST_MULT( (*xrp0 - *xrp1), sq2 );
                     *xrp0++ = temp; xrp1++;
                  }
               }
               else { // ispos != is_illegal
                  k0 = pow_iok0[ ispos ];
                  k1 = pow_iok1[ ispos ];
                  while( sb-- ) {
                     temp = ST_MULT( *xrp0, k0 );
                     *xrp1 = ST_MULT( *xrp0, k1 );
                     *xrp0++ = temp; xrp1++;
                  }
               }
               sfb++;
            }
         }
         if( gi->mixed_block_flag ) {
            INT16 sfb_max = (lsf)?6:8;
            xrp0 = xr; xrp1 = &xr[ MPA_GRANULE_SIZE ];

            if( max_sfb <= 3 ) { // Top of nul bands in long blocks
               sfb = mps->sfb_nul_l[ 1 ]; // Begin of nul bands
            }
            else {
               sfb = sfb_max; // Begin of nul band not in long blocks
            }
            sb = band_l[ sfb ];
//            is_illegal = (lsf)?mps->is_max_l[ 0 ]:7; // removed ...
            // Implicit: ispos == is_illegal here (not nul bands)
//            ispos = is_illegal; // removed becoz assigned just after for( ; ...)
            if( ms_stereo ) while( sb--) {
               temp = ST_MULT( (*xrp0 + *xrp1), sq2 );
               *xrp1 = ST_MULT( (*xrp0 - *xrp1), sq2 );
               *xrp0++ = temp; xrp1++;
            }
            else {
               xrp0 += sb;
               xrp1 += sb;
            }
            for( ; sfb<sfb_max; sfb++ ) {
               sb = band_l[ sfb+1 ] - band_l[ sfb ];
               ispos = sf->l[ sfb ];
               is_illegal = (lsf)?mps->is_max_l[ sfb ]:7;
               if( ispos == is_illegal ) {
                  if( ms_stereo ) while( sb-- ) {
                     temp = ST_MULT( (*xrp0 + *xrp1), sq2 );
                     *xrp1 = ST_MULT( (*xrp0 - *xrp1), sq2 );
                     *xrp0++ = temp; xrp1++;
                  }
                  else {
                     xrp0 += sb;
                     xrp1 += sb;
                  }
               }
               else { // ispos != is_illegal
                  k0 = pow_iok0[ ispos ];
                  k1 = pow_iok1[ ispos ];
                  while( sb-- ) {
                     temp = ST_MULT( *xrp0, k0 );
                     *xrp1 = ST_MULT( *xrp0, k1 );
                     *xrp0++ = temp; xrp1++;
                  }
               }
            }
         }
      }
      else { // Long blocks, intensity stereo

         // #9 Begin
         sbmax = mps->sfb_nul_l[ 0 ];
         if( sbmax < mps->sfb_nul_l[ 1 ] ) sbmax = mps->sfb_nul_l[ 1 ];
         sbmax++;
         if( sbmax > 22 ) sbmax = 22;
         // #9 End

         xrp0 = xr; xrp1 = &xr[ MPA_GRANULE_SIZE ];

         sfb = mps->sfb_nul_l[ 1 ]; // Begin of nul bands
         sb = band_l[ sfb ];
         is_illegal = (lsf)?mps->is_max_l[ 0 ]:7;
         // Implicit: ispos == is_illegal here (not nul bands)
         ispos = is_illegal;
         if( ms_stereo ) while( sb--) {
            temp = ST_MULT( (*xrp0 + *xrp1), sq2 );
            *xrp1 = ST_MULT( (*xrp0 - *xrp1), sq2 );
            *xrp0++ = temp; xrp1++;
         }
         else {
            xrp0 += sb;
            xrp1 += sb;
         }
         for( ; sfb<sbmax; sfb++ ) { // #9: sbmax instead of 22
            sb = band_l[ sfb+1 ] - band_l[ sfb ];
            if( sfb < 21 ) {
               ispos = sf->l[ sfb ]; // keep previous ispos for last sfb
               is_illegal = (lsf)?mps->is_max_l[ sfb ]:7;
            }
            if( ispos == is_illegal ) {
               if( ms_stereo ) while( sb-- ) {
                  temp = ST_MULT( (*xrp0 + *xrp1), sq2 );
                  *xrp1 = ST_MULT( (*xrp0 - *xrp1), sq2 );
                  *xrp0++ = temp; xrp1++;
               }
               else {
                  xrp0 += sb;
                  xrp1 += sb;
               }
            }
            else { // ispos != is_illegal
               k0 = pow_iok0[ ispos ];
               k1 = pow_iok1[ ispos ];
               while( sb-- ) {
                  temp = ST_MULT( *xrp0, k0 );
                  *xrp1 = ST_MULT( *xrp0, k1 );
                  *xrp0++ = temp; xrp1++;
               }
            }
         }
      }
   }
   else if( (mps->stereo) && ms_stereo ) { // MS stereo

      xrp0 = xr; xrp1 = &xr[ MPA_GRANULE_SIZE ];

      // #9 Begin
      sb = mps->imdct_max[ 0 ];
      if( sb < mps->imdct_max[ 1 ] ) sb = mps->imdct_max[ 1 ];
      sb = (INT16)(sb+1) * MPA_SSLIMIT;
      if( sb > MPA_GRANULE_SIZE ) sb = MPA_GRANULE_SIZE;
      // #9 End

      while( sb-- ) {
         temp = ST_MULT( (*xrp0 + *xrp1), sq2 );
         *xrp1 = ST_MULT( (*xrp0 - *xrp1), sq2 );
         *xrp0++ = temp; xrp1++; // WARNING Lattice Wrong optimize *xrp1++ = (*xrp0 - *xrp1) * sq2 !!!

      }
   }
   else { //Normal stereo or mono -> nothing to do !
      // Nothing
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_stereo */


// #8 Begin
static int MPEG3_stereo_mono( MPA_STREAM *mps, MPEGAUD_FRACT_TYPE *xr, INT16 gr )
/*--------------------------------------------------------------------------
   Decode the stereo data -> mono of a granule
   Return 0 if Ok
*/
{
   const INT16 *band_l = sfBandIndex_l[ mps->header.ID ][ mps->header.sampling_frequency ];
   const INT16 *band_s = sfBandIndex_s[ mps->header.ID ][ mps->header.sampling_frequency ];
   MPA_SCALE_FAC3 *sf = &mps->scale_fac3[ 1 ];
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ 0 ].gr[ gr ];

   BOOL ms_stereo = (mps->header.mode == MPA_MODE_JOINT_STEREO) &&
                    (mps->header.mode_extension & 0x2);
   BOOL i_stereo = (mps->header.mode == MPA_MODE_JOINT_STEREO) &&
                   (mps->header.mode_extension & 0x1);

   INT16 sfb;
   INT16 i, j, sb, sbmax; // #9: sbmax

   BOOL lsf = (mps->header.ID == MPA_ID_2);

   #define MAX_POS1 7
   #define MAX_POS2 32

   const ST_TYPE *pow_iok0;
   register MPEGAUD_FRACT_TYPE *xrp0, *xrp1;
#ifdef MPEGAUD_INT
   register ST_TYPE sq2 = 0.7071067812 * (1<<ST_BITS);
#else
   register REAL sq2 = 0.7071067812;
#endif

   if( lsf ) {
      if( gi->scalefac_compress & 1 ) {
         pow_iok0 = pow_io0[ 1 ];
      }
      else {
         pow_iok0 = pow_io0[ 0 ];
      }
   }
   else {
      pow_iok0 = tan_pos0;
   }

MPEGAUD_CHECK_DEMO;

   if( (mps->stereo) && i_stereo ) {
      ST_TYPE k0;
      INT16 sfb_top;
      INT16 max_sfb = 0;
      INT16 ispos;
      INT16 is_illegal;

      if( gi->window_switching_flag && (gi->block_type == 2) ) {
         // #9 Begin
         sbmax = mps->sfb_nul_s_top[ 0 ];
         if( sbmax < mps->sfb_nul_s_top[ 1 ] ) sbmax = mps->sfb_nul_s_top[ 1 ];
         sbmax++;
         if( sbmax > 13 ) sbmax = 13;
         // #9 End

         for( j=0; j<3; j++ ) {
            sfb_top = mps->sfb_nul_s[ j ][ 1 ];
            if( (gi->mixed_block_flag) && (sfb_top < 3) ) sfb_top = 3; // Normaly not !!!
            if( sfb_top > max_sfb ) max_sfb = sfb_top;

            is_illegal = (lsf)?mps->is_max_s[ j ][ 0 ]:7;
            // Implicit: ispos == is_illegal here (not nul bands)
            ispos = is_illegal;
            for( sfb=0; sfb<sfb_top; sfb++ ) {
               sb = band_s[ sfb+1 ] - band_s[ sfb ];

               i = 3 * band_s[ sfb ] + j * sb;
               xrp0 = &xr[ i ]; xrp1 = &xr[ MPA_GRANULE_SIZE + i ];

               if( ms_stereo ) while( sb-- ) {
                  *xrp0 = ST_MULT( (*xrp0 + *xrp1), sq2 );
                  xrp0++; xrp1++;
               }
            }
            while( sfb < sbmax ) { // #9: sbmax instead of 13
               sb = band_s[ sfb+1 ] - band_s[ sfb ];

               i = 3 * band_s[ sfb ] + j * sb;
               xrp0 = &xr[ i ]; xrp1 = &xr[ MPA_GRANULE_SIZE + i ];

               if( sfb < 12 ) {
                  ispos = sf->s[ j ][ sfb ]; // keep previous ispos for last sfb
                  is_illegal = (lsf)?mps->is_max_s[ j ][ sfb ]:7;
               }
               if( ispos == is_illegal ) {
                  if( ms_stereo ) while( sb-- ) {
                     *xrp0 = ST_MULT( (*xrp0 + *xrp1), sq2 );
                     xrp0++; xrp1++;
                  }
               }
               else { // ispos != is_illegal
                  k0 = pow_iok0[ ispos ];
//                  xrp1 += sb;
                  while( sb-- ) {
                     *xrp0 = ST_MULT( *xrp0, k0 );
                     xrp0++;
                  }
               }
               sfb++;
            }
         }
         if( gi->mixed_block_flag ) {
            INT16 sfb_max = (lsf)?6:8;
            xrp0 = xr; xrp1 = &xr[ MPA_GRANULE_SIZE ];

            if( max_sfb <= 3 ) { // Top of nul bands in long blocks
               sfb = mps->sfb_nul_l[ 1 ]; // Begin of nul bands
            }
            else {
               sfb = sfb_max; // Begin of nul band not in long blocks
            }
            sb = band_l[ sfb ];
            // Implicit: ispos == is_illegal here (not nul bands)
            if( ms_stereo ) while( sb--) {
               *xrp0 = ST_MULT( (*xrp0 + *xrp1), sq2 );
               xrp0++; xrp1++;
            }
            else {
               xrp0 += sb;
               xrp1 += sb;
            }
            for( ; sfb<sfb_max; sfb++ ) {
               sb = band_l[ sfb+1 ] - band_l[ sfb ];
               ispos = sf->l[ sfb ];
               is_illegal = (lsf)?mps->is_max_l[ sfb ]:7;
               if( ispos == is_illegal ) {
                  if( ms_stereo ) while( sb-- ) {
                     *xrp0 = ST_MULT( (*xrp0 + *xrp1), sq2 );
                     xrp0++; xrp1++;
                  }
                  else {
                     xrp0 += sb;
                     xrp1 += sb;
                  }
               }
               else { // ispos != is_illegal
                  k0 = pow_iok0[ ispos ];
                  xrp1 += sb;
                  while( sb-- ) {
                     *xrp0 = ST_MULT( *xrp0, k0 );
                     xrp0++;
                  }
               }
            }
         }
      }
      else { // Long blocks, intensity stereo

         // #9 Begin
         sbmax = mps->sfb_nul_l[ 0 ];
         if( sbmax < mps->sfb_nul_l[ 1 ] ) sbmax = mps->sfb_nul_l[ 1 ];
         sbmax++;
         if( sbmax > 22 ) sbmax = 22;
         // #9 End

         xrp0 = xr; xrp1 = &xr[ MPA_GRANULE_SIZE ];

         sfb = mps->sfb_nul_l[ 1 ]; // Begin of nul bands
         sb = band_l[ sfb ];
         is_illegal = (lsf)?mps->is_max_l[ 0 ]:7;
         // Implicit: ispos == is_illegal here (not nul bands)
         ispos = is_illegal;
         if( ms_stereo ) while( sb--) {
            *xrp0 = ST_MULT( (*xrp0 + *xrp1), sq2 );
            xrp0++; xrp1++;
         }
         else {
            xrp0 += sb;
            xrp1 += sb;
         }
         for( ; sfb<sbmax; sfb++ ) { // #9: sbmax instead of 22
            sb = band_l[ sfb+1 ] - band_l[ sfb ];
            if( sfb < 21 ) {
               ispos = sf->l[ sfb ]; // keep previous ispos for last sfb
               is_illegal = (lsf)?mps->is_max_l[ sfb ]:7;
            }
            if( ispos == is_illegal ) {
               if( ms_stereo ) while( sb-- ) {
                  *xrp0 = ST_MULT( (*xrp0 + *xrp1), sq2 );
                  xrp0++; xrp1++;
               }
               else {
                  xrp0 += sb;
                  xrp1 += sb;
               }
            }
            else { // ispos != is_illegal
               k0 = pow_iok0[ ispos ];
               xrp1 += sb;
               while( sb-- ) {
                  *xrp0 = ST_MULT( *xrp0, k0 );
                  xrp0++;
               }
            }
         }
      }
   }
   else if( (mps->stereo) && ms_stereo ) { // MS stereo

      xrp0 = xr; xrp1 = &xr[ MPA_GRANULE_SIZE ];

      // #9 Begin
      sb = mps->imdct_max[ 0 ];
      if( sb < mps->imdct_max[ 1 ] ) sb = mps->imdct_max[ 1 ];
      sb = (INT16)(sb+1) * MPA_SSLIMIT;
      if( sb > MPA_GRANULE_SIZE ) sb = MPA_GRANULE_SIZE;
      // #9 End

      while( sb-- ) {
         *xrp0 = ST_MULT( (*xrp0 + *xrp1), sq2 );
         xrp0++; xrp1++;
      }
   }
   else { //Normal stereo or mono -> nothing to do !
      // Nothing
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_stereo_mono */

// #8 End

static int MPEG3_reorder( MPA_STREAM *mps, MPEGAUD_FRACT_TYPE *xr,
                          MPEGAUD_FRACT_TYPE *ro, INT16 gr, INT16 ch )
/*--------------------------------------------------------------------------
   Reorder a granule (block type 2)
   Return 0 if Ok
*/
{
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ ch ].gr[ gr ];
   register MPEGAUD_FRACT_TYPE *pro;
   register MPEGAUD_FRACT_TYPE *pxr0, *pxr1, *pxr2;
   const INT16 *sfbindex;
   INT16 sfb, freq;
   INT16 sfb_start, sfb_lines;

   // In ISO/IEC 11172-3 window_switching_flag is set if window type <> 0
   // so, must be set if gi->block_type == 2 !
   if( gi->window_switching_flag && (gi->block_type == 2) ) {
      pro = ro;
      pxr2 = xr;
      sfbindex = sfBandIndex_s[ mps->header.ID ][ mps->header.sampling_frequency ];
      sfb = 13;
      if( gi->mixed_block_flag ) { // No Reorder for the 2 first subbands
         freq = (2*MPA_SSLIMIT);
         while( freq-- ) *pro++ = *pxr2++;
         sfb -= 3;
         sfbindex += 3;
      }

MPEGAUD_CHECK_DEMO;

      while( sfb-- ) {
         sfb_start = *sfbindex++;
         sfb_lines = *sfbindex - sfb_start;
         pxr0 = pxr2;
         pxr1 = pxr0 + sfb_lines;
         pxr2 = pxr1 + sfb_lines;
         freq = sfb_lines;
         while( freq-- ) {
            *pro++ = *pxr0++;
            *pro++ = *pxr1++;
            *pro++ = *pxr2++;
         }
      }
   }
   else {   // Long blocks are in good order
      memcpy( ro, xr, MPA_GRANULE_SIZE * sizeof(MPEGAUD_FRACT_TYPE) );
   }

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_reorder */


#ifdef MPEGAUD_INT
#define ALIAS_TYPE INT16
#define ALIAS_BITS 15
#define ALIAS_MULT( bu, cx ) (((bu) * (cx))>>(ALIAS_BITS))
#else
#define ALIAS_TYPE REAL
#define ALIAS_MULT( bu, cx ) ((bu) * (cx))
#endif

static int MPEG3_antialias( MPA_STREAM *mps, MPEGAUD_FRACT_TYPE *xr,
                            INT16 gr, INT16 ch, INT16 sb_max )
/*--------------------------------------------------------------------------
   Apply the antialiasing buterfflies on a granule
   Return 0 if Ok
*/
{
   MPA_GRANULE_INFO *gi = &mps->side_info.ch[ ch ].gr[ gr ];

#if !defined(ASM_OPTIMIZE) && !defined(COLDFIRE_ASM_2)
#ifdef MPEGAUD_INT
   // Pre-calc tables for ALIAS_BITS=15
   static const ALIAS_TYPE ca[ 8 ] = {
      -16858, -15457, -10268, -5960, -3099, -1342, -465, -121,
   };
   static const ALIAS_TYPE cs[ 8 ] = {
      28098, 28892, 31117, 32221, 32621, 32740, 32764, 32767,
   };
#else
   static const ALIAS_TYPE ca[ 8 ] = {
      -0.514495730, -0.471731961, -0.313377440, -0.181913197,
      -0.094574191, -0.040965579, -0.014198568, -0.003699975,
   };
   static const ALIAS_TYPE cs[ 8 ] = {
      0.857492924, 0.881741941, 0.949628592, 0.983314574,
      0.995517790, 0.999160528, 0.999899149, 0.999993145,
   };
#endif

   INT16 sb, ss, i;
   register MPEGAUD_FRACT_TYPE *bu, *bd;  // upper and lower butterfly inputs
   register const ALIAS_TYPE *csi, *cai;
   register MPEGAUD_FRACT_TYPE obu;       // temp butterfly output
#endif

   INT16 sblim;

   if( gi->window_switching_flag && (gi->block_type == 2) ) {
      if( !gi->mixed_block_flag ) return MPEGDEC_ERR_NONE;
      sblim = 1;
   }
   else sblim = sb_max-1;

#if defined(ASM_OPTIMIZE) || defined(COLDFIRE_ASM_2)
#ifdef MPEGAUD_INT
   MPEGSUBB_antialias( xr, sblim );
#else
   MPEGSUBF_antialias( xr, sblim );
#endif
#else
   i = MPA_SSLIMIT-1;
   for( sb=0; sb<sblim; sb++ ) {
      bu = &xr[ i ];
      bd = bu+1;
      i += MPA_SSLIMIT;
      csi = cs; cai = ca;
      for( ss=0; ss<8; ss++ ) {
         obu = ALIAS_MULT( *bu, *csi ) - ALIAS_MULT( *bd, *cai );
         *bd = ALIAS_MULT( *bd, *csi ) + ALIAS_MULT( *bu, *cai );
         *bu = obu;
         csi++; cai++;
         bd++;
         bu--;
      }
   }
#endif

MPEGAUD_CHECK_DEMO;

   return MPEGDEC_ERR_NONE;

} /* MPEG3_antialias */

// #10 Begin
#if 0
static INT16 MPEG3_imdct_number( MPA_STREAM *mps, INT16 gr )
/*--------------------------------------------------------------------------
   Estimate the number of imdct not nul of  a granule
*/
{
   const INT16 *band_l = sfBandIndex_l[ mps->header.ID ][ mps->header.sampling_frequency ];
   const INT16 *band_s = sfBandIndex_s[ mps->header.ID ][ mps->header.sampling_frequency ];

   INT16 bmax = 0;
   INT16 b, ch, w;
   INT16 imdct_nb;
   INT16 channels = (mps->force_mono)?1:mps->channels; // #8

   for( ch=0; ch<channels; ch++ ) { // #8: channels
      if( mps->side_info.ch[ ch ].gr[ gr ].block_type == 2 ) {
         b = 0;
         for( w=0; w<3; w++ ) {
            if( band_s[ mps->sfb_nul_s[ w ][ ch ] ] > b ) b = band_s[ mps->sfb_nul_s[ w ][ ch ] ]; // #2
         }
         b *= 3;
      }
      else {
         b = band_l[ mps->sfb_nul_l[ ch ] ];
      }
      if( b > bmax ) bmax = b;
   }
   imdct_nb = 1 + ((bmax + (MPA_SSLIMIT-1)) / MPA_SSLIMIT);
   if( imdct_nb > mps->sb_max ) imdct_nb = mps->sb_max;
   if( imdct_nb > MPA_SBLIMIT ) imdct_nb = MPA_SBLIMIT;

//printf( "imdctmax=%3d new=%3d, %3d\n", imdct_nb, mps->imdct_max[ 0 ], mps->imdct_max[ 1 ] );
   return imdct_nb;

} /* MPEG3_imdct_number */
#endif
// #10 End

int MPEG3_reset( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Reset the decoder
*/
{
   int err;
   HUFFMAN *h = mps->huffman;

   // Reset the huffman decoder
   err = HUFF_reset( h );

   return err;

} /* MPEG3_reset */

INT32 MPEG3_decode_frame( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the current frame
   Return # of decoded samples
*/
{
   INT16 max_gr, gr, ch;
   int slots;
   BITSTREAM *bs = mps->bitstream;
   HUFFMAN *h = mps->huffman;
   register char byte;
   int status;
   int start, seek_pos;
   INT16 pcm_offset[ 2 ];
   INT16 sb_max;
   INT16 channels = (mps->force_mono)?1:mps->channels;
   int err;

#define ERR_CHECK( i ) err = i;  if( err ) {printf("Error %d in decode_frame\n", i); return err;}

MPEGAUD_CHECK_DEMO;

   ERR_CHECK( MPEG3_decode_side_info( mps ) );

   status = HUFF_set_start( h, mps->side_info.main_data_begin );
   slots = MPEG3_main_data_slots( mps );

/* #6 Begin */
   {
      char buffer[ 1440 ]; // 1440 is the max theorical value for layer III (#11 suppressed static)
      int i;

      while (slots > 0) {
	i = (slots > 1440) ? 1440 : slots;
        BSTR_read_bytes( bs, slots, buffer );
#ifdef USE_RC4
	if (mps->header.private_bit) {
		if (mps->keyp == NULL)
			return(-1);
		RC4(mps->keyp, slots, buffer, buffer);
	}
#endif
        HUFF_fill_bytes( h, slots, buffer );
	slots -= i;
      }
   }
/* #6 End */

   if( BSTR_end( bs ) ) return MPEGDEC_ERR_EOF; // #2

   if( status ) {
     //     printf("Can't decode this frame (not enough data)\n");
      return 0; // Can't decode this frame (not enough data)
   }

   max_gr = (mps->header.ID == MPA_ID_1)?2:1;

   pcm_offset[ 0 ] = pcm_offset[ 1 ] = 0;
   seek_pos = HUFF_pos( h );
   for( gr=0; gr<max_gr; gr++ ) {
      for( ch=0; ch<mps->channels; ch++ ) {
         // WE HAVE TO SEEK IN HUFFMAN DATA
         // use part2_3_length of each granule
         HUFF_seek( h, seek_pos );
         start = HUFF_pos( h );
         // calculate next seek position with actual part2_3_length
         seek_pos += mps->side_info.ch[ ch ].gr[ gr ].part2_3_length;
         if( mps->header.ID == MPA_ID_1 ) {
            ERR_CHECK( MPEG3_decode_scale1( mps, gr, ch ) );
         }
         else {
            ERR_CHECK( MPEG3_decode_scale2( mps, gr, ch ) );
         }
         ERR_CHECK( MPEG3_huffman_decode( mps, mps->is, gr, ch, start ) );
         MPEG3_get_nul_pos( mps, mps->is, gr, ch ); // #10
         ERR_CHECK( MPEG3_dequantize_samples( mps, mps->is, &mps->xr[ ch ][ 0 ], gr, ch ) );
      }

      if( channels == 2 ) { // #8
         ERR_CHECK( MPEG3_stereo( mps, &mps->xr[ 0 ][ 0 ], gr ) );
      }
      else if( (channels == 1) && (mps->channels == 2) ) {
         ERR_CHECK( MPEG3_stereo_mono( mps, &mps->xr[ 0 ][ 0 ], gr ) );
      }

//      sb_max = MPEG3_imdct_number( mps, gr ); // #10
      for( ch=0; ch<channels; ch++ ) {
         INT16 ss;
         MPEGAUD_FRACT_TYPE *sub;
         INT16 *pcm;
         sb_max = mps->imdct_max[ ch ]; // #10
         pcm = mps->pcm[ ch ];
         if( mps->side_info.ch[ ch ].gr[ gr ].window_switching_flag &&
             (mps->side_info.ch[ ch ].gr[ gr ].block_type == 2) ) {
            ERR_CHECK( MPEG3_reorder( mps, &mps->xr[ ch ][ 0 ], &mps->lr[ 0 ][ 0 ], gr, ch ) );
            ERR_CHECK( MPEG3_antialias( mps, &mps->lr[ 0 ][ 0 ], gr, ch, sb_max ) );
            sub = &mps->lr[ 1 ][ 0 ];
            MPEGIMDCT_hybrid( mps->mpegimdct, &mps->lr[ 0 ][ 0 ], sub,
                              mps->side_info.ch[ ch ].gr[ gr ].block_type,
                              (BOOL)mps->side_info.ch[ ch ].gr[ gr ].mixed_block_flag,
                              ch, sb_max ); // #4

         }
         else {
            ERR_CHECK( MPEG3_antialias( mps, &mps->xr[ ch ][ 0 ], gr, ch, sb_max ) );
            sub = &mps->lr[ 1 ][ 0 ];
            MPEGIMDCT_hybrid( mps->mpegimdct, &mps->xr[ ch ][ 0 ], sub,
                              mps->side_info.ch[ ch ].gr[ gr ].block_type,
                              (BOOL)mps->side_info.ch[ ch ].gr[ gr ].mixed_block_flag,
                              ch, sb_max ); // #4
         }
         for( ss=0; ss<MPA_SSLIMIT; ss++ ) {
            pcm_offset[ ch ] += MPEGSUB_synthesis( mps->mpegsub, sub, ch, &pcm[ pcm_offset[ ch ] ] );
            sub += MPA_SBLIMIT;
         }
      }
   }
   HUFF_seek( h, seek_pos );

   return (INT32)pcm_offset[ 0 ];

} /* MPEG3_decode_frame */

