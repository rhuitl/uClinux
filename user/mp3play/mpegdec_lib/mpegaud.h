/*------------------------------------------------------------------------------

    File    :   MPEGAUD.H

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
    0   |19/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |06/04/1997| Added MPEG2.5 (not ISO standard)                     ST
    3   |07/05/1997| Added MPEGAUD_DEMO                                   ST
    4   |27/05/1997| Added MPEGIMDCT                                      ST
    5   |16/06/1997| Added need_sync                                      ST
    6   |13/07/1997| Added imdct_max & sfb_nul_s_top                      ST
    7   |16/06/1998| Added bitstream_start_pos                            ST
    8   |24/05/1999| Suppressed all static vars to allow multi-decoding   ST

    ------------------------------------------------------------------------

    MPEG Audio defintions

------------------------------------------------------------------------------*/

#ifndef MPEGAUD_H
#define MPEGAUD_H

//#define MPEGAUD_DEMO 512 // Defined if limited demo version (limited to 500 frames)

#ifdef MPEGAUD_DEMO
#define MPEGAUD_CHECK_DEMO_FRAME( frame ) if( frame >= MPEGAUD_DEMO ) return -1
#define MPEGAUD_CHECK_DEMO if( mps->frame >= MPEGAUD_DEMO ) return -1
#else
#define MPEGAUD_CHECK_DEMO_FRAME( frame )
#define MPEGAUD_CHECK_DEMO
#endif

//#define MPEGAUD_INT // For integer decoding

#include "bitstr.h"
#include "huff.h"

/* ID */

#define MPA_ID_1              1
#define MPA_ID_2              0

/* Sampling Frequencies */

#define MPA_SAMP_44100        0
#define MPA_SAMP_48000        1
#define MPA_SAMP_32000        2

/* Modes */

#define MPA_MAX_CHANNELS      2

#define MPA_MODE_STEREO       0
#define MPA_MODE_JOINT_STEREO 1
#define MPA_MODE_DUAL_CHANNEL 2
#define MPA_MODE_MONO         3

#define MPA_SSLIMIT 18
#define MPA_SBLIMIT 32

#define MPA_GRANULE_SIZE 576  // MPA_SSLIMIT*MPA_SBLIMIT

#define MPA_SCALE_BLOCK 12
#define MPA_HANNING_SIZE 512
#define MPA_SCALE_RANGE 64
#define MPA_SCALE 32768
#define MPA_PCM_SIZE 1152

// Layer II
#define MPA_GROUPS  3

// Layer III
#define MPA_MAX_GRANULES 2
#define MPA_MAX_WINDOWS  3

typedef struct {
   INT16 ID;
   INT16 layer;
   INT16 protection_bit;
   INT16 bitrate_index;
   INT16 sampling_frequency;
   BOOL  padding_bit;
   BOOL  private_bit;
   INT16 mode;
   INT16 mode_extension;
   BOOL  copyright;
   BOOL  original;
   INT16 emphasis;
   INT16 crc_check;
   BOOL  half_freq; // MPEG 2.5 ext. (#2)
   INT32 header_pos; // #7
} MPA_HEADER;

// Layer III granule info
typedef struct {
   UINT16 part2_3_length;        // 12 uimsbf
   UINT16 big_values;            // 9  uimsbf
   UINT16 global_gain;           // 8  uimsbf
   UINT16 scalefac_compress;     // 4  bslbf MPEG1, 9 bslbf MPEG2
   BOOL   window_switching_flag;
   UINT16 block_type;            // 2  bslbf
   BOOL   mixed_block_flag;
   UINT16 table_select[ 3 ];     // 5  bslbf
   UINT16 subblock_gain[ 3 ];    // 3  bslbf
   UINT16 region0_count;         // 4  bslbf
   UINT16 region1_count;         // 3  bslbf
   BOOL   preflag;
   BOOL   scalefac_scale;        // 1 bslbf
   UINT16 count1table_select;    // 1 bslbf
} MPA_GRANULE_INFO;

// Layer III side info
typedef struct {
   UINT16 main_data_begin;       // 9  uimsbf MPEG1, 8 uimsbf MPEG2
   UINT16 private_bits;          // 5/3 bslbf MPEG1, 1/2 bslbf MPEG2
   struct {
      BOOL scfsi[ 4 ];
      MPA_GRANULE_INFO gr[ MPA_MAX_GRANULES ];
   } ch[ MPA_MAX_CHANNELS ];
} MPA_SIDE_INFO;

// Layer III scale factors
// Note : swap  s[ MPA_MAX_WINDOWS ][ 13 ] to s[ 13 ][ MPA_MAX_WINDOWS ]
//        to optimize time access ?
typedef struct {
   UINT16 l[ 23 ];
   UINT16 s[ MPA_MAX_WINDOWS ][ 13 ];
} MPA_SCALE_FAC3;


#ifdef MPEGAUD_INT
#define MPEGAUD_SCALE_TYPE INT32
//#define MPEGAUD_SCALE_BITS 15
#define MPEGAUD_SCALE_BITS 30
#define MPEGAUD_FRACT_TYPE INT16
#define MPEGAUD_FRACT_BITS 14
#else
#define MPEGAUD_SCALE_TYPE REAL
#define MPEGAUD_FRACT_TYPE REAL
#endif

#include "mpegsub.h"
#include "mpegimdc.h" // #4

// Warning: assume 32-bit alignement

typedef struct {
   const UINT8 (*alloc)[ 16 ]; // MPEG-II alloc table
   INT16 bit_alloc[ MPA_MAX_CHANNELS ][ MPA_SBLIMIT ];
   MPEGAUD_SCALE_TYPE scale[ MPA_MAX_CHANNELS ][ MPA_GROUPS ][ MPA_SBLIMIT ];
   UINT16 sample[ MPA_MAX_CHANNELS ][ MPA_GROUPS ][ MPA_SBLIMIT ];
   MPEGAUD_FRACT_TYPE fraction[ MPA_MAX_CHANNELS ][ MPA_GROUPS ][ MPA_SBLIMIT ];

   INT16 is[ MPA_GRANULE_SIZE ];
   MPEGAUD_FRACT_TYPE xr[ MPA_MAX_CHANNELS ][ MPA_GRANULE_SIZE ];
   MPEGAUD_FRACT_TYPE lr[ MPA_MAX_CHANNELS ][ MPA_GRANULE_SIZE ];

   INT16 *pcm[ MPA_MAX_CHANNELS ];
   INT16 scfsi[ MPA_MAX_CHANNELS ][ MPA_SBLIMIT ];
//   MPEGAUD_FRACT_TYPE prevblk[ MPA_MAX_CHANNELS ][ MPA_GRANULE_SIZE ]; // #4: deleted
   MPA_SCALE_FAC3 scale_fac3[ MPA_MAX_CHANNELS ];

   BITSTREAM *bitstream;
   HUFFMAN *huffman;
   MPEGSUB *mpegsub;
   MPEGIMDCT *mpegimdct; // #4

   MPA_HEADER header;
   MPA_SIDE_INFO side_info;
   BOOL  stereo;
   INT16 channels;
   UINT16 sfreq;
   UINT32 stream_size;
   INT16 bitrate;
   INT16 jsbound;
   INT16 sblimit;
   INT16 current_table;
   UINT32 frame;

   INT16 freq_div;
   INT16 quality;
   INT16 sb_max;
   BOOL force_mono;

   INT16 sfb_nul_l[ MPA_MAX_CHANNELS ];
   INT16 sfb_nul_s[ MPA_MAX_WINDOWS ][ MPA_MAX_CHANNELS ];
   // For MPEG2-III is_pos illegal is not 7 but is_max[ sfb ]
   INT16 is_max_l[ 21 ];
   INT16 is_max_s[ MPA_MAX_WINDOWS ][ 12 ];

   BOOL need_sync; // #5
   INT16 imdct_max[ MPA_MAX_CHANNELS ]; // #6
   INT16 sfb_nul_s_top[ MPA_MAX_WINDOWS ]; // #6

   INT32 bitstream_start_pos; // #7
   void *keyp;
} MPA_STREAM;

#endif /* MPEGAUD_H */
