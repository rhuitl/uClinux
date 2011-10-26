/*------------------------------------------------------------------------------

    File    :   MPEGDEC.C
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
    0   |19/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |06/04/1997| Take care of MPEG2.5                                 ST
    3   |24/04/1997| Added MPEGDEC_seek, MPEGDEC_time                     ST
    4   |27/04/1997| Added freq_max in MPEGDEC_CTRL                       ST
    5   |18/05/1997| Added tolerance in header sync, CTRL of first sync   ST
    6   |22/05/1997| Added check_mpeg in MPEGDEC_CTRL                     ST
    6   |22/05/1997| Added bitstream buffer size config in MPEGDEC_CTRL   ST
    7   |23/05/1997| Added MPEGDEC_ERR_xxx                                ST
    8   |27/05/1997| Added MPEGIMDCT                                      ST
    9   |07/06/1997| Added synchronize                                    ST
    10  |16/06/1997| Added need_sync                                      ST
    11  |17/06/1997| Corrected MPEGDEC_seek                               ST
    12  |03/07/1997| Corrected synchronization when error protection      ST
    13  |06/07/1997| Use different setting for layer I & II and layer III ST
    14  |15/07/1997| Added dec_quality                                    ST
    15  |20/09/1997| Added MPEGDEC_find_sync                              ST
    16  |26/03/1998| Modify synchronize for variable bitrates             ST
    17  |16/06/1998| Enhanced synchronize for to keep first good frame    ST
    18  |21/06/1998| Added MPEGDEC_scale                                  ST
    19  |01/09/1999| Spawnd MP3 only version frmo mp3dec.c                RS

    ------------------------------------------------------------------------

    MPEG 3 only Audio decoder ...

    
-----------------------------------------------------------------------------*/

#include "defs.h"
#include "mpegaud.h"
#include "mpeg3dec.h"
#include "mpegdec.h"
#include "mpegtab.h"

#ifdef USE_RC4
#include "rc4.h"
#endif

#define MPEGDEC_BITSTREAM_BUFFER_SIZE 16384 // #6 Now default buffer size

#ifdef MPEGAUD_DEMO
static frame_count = 0;
#endif

static int MPEGDEC_decode_header( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Decode the current Header
   Return 0 if Ok
*/
{
   MPA_HEADER *mph = &mps->header;
   INT16 bitrate_per_channel;
   INT16 table;

   mps->bitrate = MPT_bitrate[ mph->ID ][ mph->layer -1 ][ mph->bitrate_index ];

   if( mph->mode == MPA_MODE_MONO ) {
      mps->stereo = FALSE;
      mps->channels = 1;
      bitrate_per_channel = mps->bitrate;
   }
   else {
      mps->stereo = TRUE;
      mps->channels = 2;
      bitrate_per_channel = mps->bitrate>>1;
   }
   mps->sfreq = MPT_freq[ mph->ID ][ mph->sampling_frequency ];
   if( !mps->sfreq ) return MPEGDEC_ERR_BADFRAME;
   if( mph->half_freq ) mps->sfreq >>= 1; // #2

   if( mph->layer == 2 ) {
      if( mph->ID == MPA_ID_1 ) {
         if( ( (mph->sampling_frequency == MPA_SAMP_48000) &&
               (bitrate_per_channel >= 56) ) ||
             ( (bitrate_per_channel >= 56) &&
               (bitrate_per_channel <= 80) ) ) table = 0;
         else if( (mph->sampling_frequency != MPA_SAMP_48000) &&
                  (bitrate_per_channel >= 96) ) table = 1;
         else if( (mph->sampling_frequency != MPA_SAMP_32000) &&
                  (bitrate_per_channel <= 48) ) table = 2;
         else table = 3;
      }
      else {
         table = 4;
      }
      mps->sblimit = MPT_sblimit[ table ];
      if( table != mps->current_table ) {
         switch( table ) {
            case 0: mps->alloc = MPT_alloc_0; break;
            case 1: mps->alloc = MPT_alloc_1; break;
            case 2: mps->alloc = MPT_alloc_2; break;
            case 3: mps->alloc = MPT_alloc_3; break;
            default: mps->alloc = MPT_alloc_4; break;
         }
         mps->current_table = table;
// *** WARNING ***
// Reset when sblimit changed (because some MPEG layer I inside layer II)
         // reset fraction's
         memset( mps->fraction, 0, MPA_MAX_CHANNELS * MPA_GROUPS * MPA_SBLIMIT * sizeof(MPEGAUD_FRACT_TYPE) );
      }
   }
   else {
      mps->sblimit = MPA_SBLIMIT;
   }

   if( mph->mode == MPA_MODE_JOINT_STEREO ) {
      mps->jsbound = MPT_jsbound[ mph->layer - 1 ][ mph->mode_extension ];
   }
   else {
      mps->jsbound = mps->sblimit;
   }
   return MPEGDEC_ERR_NONE;

} /* MPEGDEC_decode_header */

static int MPEGDEC_read_header( MPA_STREAM *mps, BOOL check )
/*--------------------------------------------------------------------------
   Read the next MPEG AUDIO Header
   #5: check: check if it's an mpeg audio stream, ie begin with a sync word
   Return MPEGDEC_ERR_EOF if end of stream reached.
*/
{
   register UINT32 value;
   register UINT32 header;
   BITSTREAM *bs;
   MPA_HEADER *mph;
   UINT8 old_first; // #5

   // #5
   // We check: Sync is either 0xFFF or 0xFFE (MPEG 2.5)
   //           Layer is not 4 (coded value is 0x0)
   //           Bitrate index is not 0xF (forbidden)
   //           Bitrate index is not 0x0 (free not supported)
   //           Frequency index is not 0x3 (reserved)
#define SYNC_VALID( v ) ( ((v & 0xFFE00000) == 0xFFE00000) &&\
                          ((v & 0x00060000) != 0x00000000) &&\
                          ((v & 0xF000) != 0xF000) &&\
                          ((v & 0xF000) != 0x0000) &&\
                          ((v & 0x0C00) != 0xC000) )
   bs = mps->bitstream;
   if( BSTR_end( bs ) ) return MPEGDEC_ERR_EOF;
   mph = &mps->header;

   // Header is: <Sync:12><ID:1><Lay:2><Prot:1>
   //            <Rate:4><Freq:2><Pad:1><Priv:1>
   //            <Mode:2><Ext:2><Copy:1><Orig:1><Emph:2>
   // Total: 32 bits
   // with <Sync> = 0xFFF for MPEG 1,2 <Sync> = 0xFFE for MPEG 2.5
   // <Rate> can't be 0xF, so use it to skip leading 0xFF

   // Seek to sync word
   old_first = bs->bits; // #5: This could be the last byte read (not always !)

   // Read first 24 bits
   value = BSTR_read_byte( bs );
   value <<= 8;
   value |= BSTR_read_byte( bs );
   value <<= 8;
   value |= BSTR_read_byte( bs );

   // Check if first sync is valid
   value <<= 8;
   if( SYNC_VALID( value ) ) { // Ok, first sync is valid
      value |= BSTR_read_byte( bs );
   }
   else { // first sync not valid -> try to use previous byte (#5 tolerance !)
      int loops = 16384; // #17
      if( check ) return MPEGDEC_ERR_BADFRAME; // Not an MPEG Stream !
      value >>= 8;
      value |= old_first << 24; // use previous byte

      while( !SYNC_VALID( value ) ) {
         value <<= 8;
         value |= BSTR_read_byte( bs );
         if( BSTR_end( bs ) ) return MPEGDEC_ERR_EOF;
         if( loops-- <=0 ) return MPEGDEC_ERR_BADFRAME; // #17
      }
   }

   mph->header_pos = BSTR_pos( bs ) - 4; // #17 (header is 4 bytes long)

   mph->half_freq = (value & 0x00100000) ? FALSE:TRUE; // #2

   header = value;

   mph->emphasis = header & 0x0003; header >>= 2;
   mph->original = header & 0x0001; header >>= 1;
   mph->copyright = header & 0x0001; header >>= 1;
   mph->mode_extension = header & 0x0003; header >>= 2;
   mph->mode = header & 0x0003; header >>= 2;
   mph->private_bit = header & 0x0001; header >>= 1;
   mph->padding_bit = header & 0x0001; header >>= 1;
   mph->sampling_frequency = header & 0x0003; header >>= 2;
   mph->bitrate_index = header & 0x000F; header >>= 4;
   mph->protection_bit = (header & 0x0001) ? FALSE:TRUE; header >>= 1;
   mph->layer = 4 - (header & 0x0003); header >>= 2;
   mph->ID = header & 0x0001;

   // Check for correct values
   if( mph->bitrate_index == 0xF ) return MPEGDEC_ERR_BADFRAME; // Already checked in sync search
   if( mph->sampling_frequency == 0x3 ) return MPEGDEC_ERR_BADFRAME;
   if( mph->layer == 4 ) return MPEGDEC_ERR_BADFRAME;

   if( mph->protection_bit ) mph->crc_check = BSTR_read_bits( bs, 16 );

   return MPEGDEC_decode_header( mps );

} /* MPEGDEC_read_header */

/* #15 Begin */

INT32 MPEGDEC_find_sync( INT8 *buffer, INT32 buffer_size )
/*--------------------------------------------------------------------------
   Find an mpeg synchronization pattern in a buffer
   This function can be use to check if a file contains MPEG audio stream
   Inputs: buffer = stream buffer to analyze
           buffer_size = need to know top of buffer (must be >= 4)
   Return the the sync position (>=0) or MPEGDEC_ERR_NO_SYNC if not found
*/
{
   register INT32 index = 0;
   register UINT32 value = 0;
   register UINT8 *b;

   b = (UINT8 *)buffer;

   while( index < buffer_size ) {
      value <<= 8;
      value |= (UINT32)(*b++);
      if( (index >= 3) && SYNC_VALID( value ) ) return (index - 3);
      index++;
   }
   return MPEGDEC_ERR_NO_SYNC;
}

/* #15 End */

/* #9 Begin */

static int synchronize( MPA_STREAM *mps )
/*--------------------------------------------------------------------------
   Synchronize the bitstream
   Return 0 if ok
*/
{
#define MAX_TRIES 9
   INT16 try = MAX_TRIES;
   int status;
   INT32 slots;

   while( try-- ) {
      status = MPEGDEC_read_header( mps, FALSE );
      if( status == MPEGDEC_ERR_EOF ) return status;

      if( status == MPEGDEC_ERR_NONE ) { // Header found
         int bitrate, sfreq, layer, id;
         MPA_HEADER *mph = &mps->header;

         id = mph->ID;
         layer = mph->layer;
         sfreq = mps->sfreq;
         bitrate = mps->bitrate;

         // Calculate the number of slots between 2 headers
         if( layer == 1 ) slots = 48000;
         else slots = 144000;
         if( (layer == 3) && (id == MPA_ID_2) ) slots >>= 1;
         slots *= bitrate;
         slots /= sfreq;
         if( mph->padding_bit ) slots++;
         // Now skip slots-4 bytes
         if( mph->protection_bit ) slots -= 6; // #12
         else slots -= 4;
         while( slots-- ) BSTR_read_byte( mps->bitstream );

         // Now check if header ok and same id, norm, (bitrate) and freq
         status = MPEGDEC_read_header( mps, TRUE );
         if( status == MPEGDEC_ERR_NONE ) {
            if( (mph->ID == id) && (mph->layer == layer) &&
//                (mps->sfreq == sfreq) && (mps->bitrate == bitrate) ) {
                (mps->sfreq == sfreq) ) { // #16
               // #17 Begin
               int err;

               err = BSTR_seek( mps->bitstream, mph->header_pos );
               if( err ) return MPEGDEC_ERR_BADFRAME;
               err = MPEGDEC_read_header( mps, TRUE );
               return err;
//               return MPEGDEC_ERR_NONE;
               // #17 End
            }
         }
         else if( status == MPEGDEC_ERR_EOF ) return status;
      }
   }
   return MPEGDEC_ERR_BADFRAME;
}
/* #9 End */

static void fill_info( MPEGDEC_STREAM *mpds )
/*--------------------------------------------------------------------------
   Fill the current MPEG Audio stream information
*/
{
   MPA_STREAM *mps;

   mps = (MPA_STREAM *)mpds->handle;

   mpds->norm          = (mps->header.ID == MPA_ID_1)?1:2;
   mpds->layer         = mps->header.layer;
   mpds->mode          = mps->header.mode;
   mpds->bitrate       = mps->bitrate;
   mpds->frequency     = mps->sfreq;
   mpds->channels      = mps->channels;
   if( mps->bitrate ) mpds->ms_duration = mps->stream_size / (mps->bitrate>>3);
   else mpds->ms_duration = 0;
   mpds->private_bit   = (INT16)mps->header.private_bit;
   mpds->copyright     = (INT16)mps->header.copyright;
   mpds->original      = (INT16)mps->header.original;

   mpds->dec_frequency = mps->sfreq / mps->freq_div;
   mpds->dec_channels  = (mps->force_mono)?1:mpds->channels;
   mpds->dec_quality   = mps->quality; // #14

} /* fill_info */

// #18 Begin
int MPEGDEC_scale( MPEGDEC_STREAM *mpds, INT32 scale_percent ) {
/*--------------------------------------------------------------------------
   Set the output scale for the current stream
   Inputs:  mpds = mpeg audio stream ptr returned by MPEGDEC_open
            scale_percent = scale factor in % to apply to the decoded output
                            100 is the nominal value
   Return 0 if Ok, MPEGDEC_ERR_BADVALUE if invalid scale
*/
   MPA_STREAM *mps;

   mps = (MPA_STREAM *)mpds->handle;
   if( MPEGSUB_scale( mps->mpegsub, scale_percent ) ) return MPEGDEC_ERR_BADVALUE;
   return MPEGDEC_ERR_NONE;
}
// #18 End

INT32 MPEGDEC_decode_frame( MPEGDEC_STREAM *mpds,
                            INT16 *pcm[ MPEGDEC_MAX_CHANNELS ] )
/*--------------------------------------------------------------------------
   Decode the current MPEG Audio frame
   Input:  mpds =  mpeg audio stream ptr returned by MPEGDEC_open
   Output: pcm[] = 16-bit samples
                   pcm[ 0 ] is mono or left voice or channel 1
                   pcm[ 1 ] is right or channel 2
   Return the number of samples

   Note: pcm[]'s be at least arrays of MPEGDEC_PCM_SIZE
         number of samples can be 0 if current frame is skipped, in case
         of error in crc or not enough data for decoding (layer III)
         number of samples = 0 does not indicate end of stream !
*/
{
   MPA_STREAM *mps;
   INT32 count;
   int err;

   mps = (MPA_STREAM *)mpds->handle;
   mps->pcm[ 0 ] = pcm[ 0 ];
   mps->pcm[ 1 ] = pcm[ 1 ];

   if( mps->need_sync ) { // #10
      err = synchronize( mps );
      if( err ) return err;
      mps->need_sync = FALSE;
   }
   else {
      err = MPEGDEC_read_header( mps, FALSE ); // #5 FALSE: don't fail if MPEG Audio sync not at first
      if( err ) return err;
   }

#ifdef MPEGAUD_DEMO
   MPEGAUD_CHECK_DEMO_FRAME( frame_count );
   frame_count++;
#endif

//fill_info( mpds );

   count = 0;

   switch( mps->header.layer ) {
      case 1:
         break;
      case 2:
         break;
      case 3:
         count = MPEG3_decode_frame( mps );
         break;
      default:
	break;
   }
   mps->frame++;

   return count;

} /* MPEGDEC_decode_frame */

static int decoder_reset( MPEGDEC_STREAM *mpds )
/*--------------------------------------------------------------------------
   Reset the decoder
   Inputs:  mpds = mpeg audio stream ptr returned by MPEGDEC_open
*/
{
   int err;
   MPA_STREAM *mps;

   if( !mpds ) return MPEGDEC_ERR_EOF;
   mps = (MPA_STREAM *)mpds->handle;

   // Reset layer 3 decoder
   err = MPEG3_reset( mps );
   if( err ) return err;

   // Reset subband buffers & offsets
   err = MPEGSUB_reset( mps->mpegsub );
   if( err ) return err; // #8
   err = MPEGIMDCT_reset( mps->mpegimdct ); // #8

   return err;

} /* decoder_reset */

int MPEGDEC_seek( MPEGDEC_STREAM *mpds, UINT32 ms_time_position )
/*--------------------------------------------------------------------------
   Seek into an MPEG Audio stream
   Inputs:  mpds = mpeg audio stream ptr returned by MPEGDEC_open
            ms_time_position = absolute time position in ms
*/
{
   int err = -1;
   MPA_STREAM *mps;

   if( !mpds ) return MPEGDEC_ERR_EOF;

   mps = (MPA_STREAM *)mpds->handle;

   if( mps ) {
      BITSTREAM *bs = mps->bitstream;
      REAL exact_seek;
      REAL slots;
      INT32 seek_pos;
      INT32 frame_bytes;
      INT32 frame; // #11

      exact_seek = ((REAL)mps->bitrate * (REAL)ms_time_position) * 0.125;
      // Calculate nearest # of frames
      if( mps->header.layer == 1 ) frame_bytes = 48000; // 384/8*1000
      else if( (mps->header.layer == 3) && (mps->header.ID == MPA_ID_2) ) frame_bytes = 72000;
      else frame_bytes = 144000;
      slots = (REAL)(frame_bytes * mps->bitrate) / (REAL)mps->sfreq;
      frame = (INT32)( exact_seek / slots );
      // Calcultate seek pos in multiple of frames
      seek_pos = (INT32)((REAL)frame * slots);
      // Here sub 1 to be sure to get header
      seek_pos--;
      if( seek_pos < 0 ) seek_pos = 0;
      seek_pos += mps->bitstream_start_pos; // #17

      err = BSTR_seek( bs, seek_pos );
      if( !err ) {
         mps->frame = frame; // #11
         decoder_reset( mpds );
         mps->need_sync = TRUE; // #10
      }
   }
   return err;

} /* MPEGDEC_seek */

int MPEGDEC_time( MPEGDEC_STREAM *mpds, UINT32 *ms_time_position )
/*--------------------------------------------------------------------------
   Get the current time position of an MPEG Audio stream
   Input:  mpds = mpeg audio stream ptr returned by MPEGDEC_open
   Output: ms_time_position = absolute time position in ms
   Return 0 if Ok
*/
{
   int err = -1;
   MPA_STREAM *mps;

   if( !mpds ) return MPEGDEC_ERR_EOF;

   mps = (MPA_STREAM *)mpds->handle;

   if( mps ) {
      INT32 frame_bits;

      if( mps->header.layer == 1 ) frame_bits = 384000; // 384*1000
      else if( (mps->header.layer == 3) && (mps->header.ID == MPA_ID_2) ) frame_bits = 576000;
      else frame_bits = 1152000;

      *ms_time_position = (UINT32)(((REAL)mps->frame * (REAL)frame_bits ) / (REAL)mps->sfreq);

      err = 0;
   }
   return err;

} /* MPEGDEC_time */


void MPEGDEC_close( MPEGDEC_STREAM *mpds )
/*--------------------------------------------------------------------------
   Close an MPEG Audio stream
   Input:  mpds =  mpeg audio stream ptr returned by MPEGDEC_open
*/
{
   MPA_STREAM *mps;

   if( !mpds ) return;

   mps = (MPA_STREAM *)mpds->handle;

   if( mps ) {
      if( mps->mpegimdct ) MPEGIMDCT_close( mps->mpegimdct ); // #8
      if( mps->mpegsub ) MPEGSUB_close( mps->mpegsub );
      if( mps->huffman ) HUFF_close( mps->huffman );
      if( mps->bitstream ) BSTR_close( mps->bitstream );
      free( mps );
   }
   free( mpds );

} /* MPEGDEC_close */

MPEGDEC_STREAM *MPEGDEC_open( char *filename, MPEGDEC_CTRL *ctrl )
/*--------------------------------------------------------------------------
   Open an MPEG Audio stream
   Inputs: filename = stream filename to decode
           ctrl = decoding controls
   Return the mpeg audio stream ptr or NULL if failed to open stream
*/
{
   MPEGDEC_STREAM *mpds;
   MPA_STREAM *mps;
   INT16 freq_div;
   INT16 quality;
   INT32 freq_max;
   INT32 buffer_size; // #6
   MPEGDEC_LAYER  *dec_lay; // #13
   MPEGDEC_OUTPUT *dec_out; // #13

   mpds = (MPEGDEC_STREAM *)malloc( sizeof( MPEGDEC_STREAM ) );
   if( !mpds ) return NULL;
   memset( mpds, 0, sizeof( MPEGDEC_STREAM ) );

   mps = (MPA_STREAM *)malloc( sizeof( MPA_STREAM ) );
   if( !mps ) {
      MPEGDEC_close( mpds );
      return NULL;
   }
   memset( mps, 0, sizeof( MPA_STREAM ) );
   mpds->handle = mps;

   // #7 Begin
   buffer_size = ctrl->stream_buffer_size & (INT32)(~3); // Multiple of 4 bytes
   if( buffer_size <= 0 ) buffer_size = MPEGDEC_BITSTREAM_BUFFER_SIZE;
   // #7 End
   mps->bitstream = BSTR_open( (BITSTREAM_ACCESS *)ctrl->bs_access,
                               filename, buffer_size /* #7 */ );

   if( !mps->bitstream ) {
      MPEGDEC_close( mpds );
      return NULL;
   }

   mps->stream_size = mps->bitstream->bitstream_size;

   mps->huffman = HUFF_open();
   if( !mps->huffman ) {
      MPEGDEC_close( mpds );
      return NULL;
   }

   mps->current_table = -1;

// #17 Begin
#if 0
   if( synchronize( mps ) ) {
      (void)MPEGDEC_close( mpds );
      return NULL;
   }
   mps->need_sync = FALSE;
   mps->bitstream_start_pos = mps->header.header_pos;
   mps->stream_size = mps->bitstream->bitstream_size - mps->bitstream_start_pos;
#else
   if( MPEGDEC_read_header( mps, (BOOL)ctrl->check_mpeg ) ) { // #6: check_mpeg
      (void)MPEGDEC_close( mpds );
      return NULL;
   }
#endif
// #17 End

   // #13 Begin
   if( mps->header.layer < 3 ) dec_lay = &ctrl->layer_1_2;
   else dec_lay = &ctrl->layer_3;

   mps->force_mono = dec_lay->force_mono;

   if( mps->stereo ) dec_out = &dec_lay->stereo;
   else dec_out = &dec_lay->mono;

   freq_div = dec_out->freq_div;
   quality = dec_out->quality;
   freq_max = dec_out->freq_max;
   // #13 End

#ifdef MPEGAUD_DEMO
   quality = 0;
#endif

   if( freq_div == 0 ) { // #4
      INT32 freq = mps->sfreq;

      mps->freq_div = 1;
      do {
         if( freq <= freq_max ) break;
         mps->freq_div <<= 1;
         freq >>= 1;
      } while ( mps->freq_div < 4 );
   }
   else {
      mps->freq_div = freq_div;
   }

   switch( mps->freq_div ) {
      case 2:
         mps->sb_max = MPA_SBLIMIT/2;
         break;
      case 4:
         mps->sb_max = MPA_SBLIMIT/4;
         break;
      default:
         mps->freq_div = 1;
         mps->sb_max = MPA_SBLIMIT;
         break;
   }
   mps->quality = quality;
   if( mps->quality < MPEGDEC_QUALITY_LOW ) mps->quality = MPEGDEC_QUALITY_LOW;
   else if( mps->quality > MPEGDEC_QUALITY_HIGH ) mps->quality = MPEGDEC_QUALITY_HIGH;

   mps->mpegsub = MPEGSUB_open( mps->freq_div, mps->quality );
   if( !mps->mpegsub ) {
      MPEGDEC_close( mpds );
      return NULL;
   }
   /* #8 Begin */
   mps->mpegimdct = MPEGIMDCT_open();
   if( !mps->mpegimdct ) {
      MPEGDEC_close( mpds );
      return NULL;
   }
   /* #8 End */

   fill_info( mpds );
   (void)BSTR_seek( mps->bitstream, /*0*/ mps->bitstream_start_pos ); // #17
   decoder_reset( mpds );

   return mpds;

} /* MPEGDEC_open */

#ifdef USE_RC4

static RC4_KEY	MPEGDEC_rc4_key;

void MPEGDEC_setkey( MPEGDEC_STREAM *mpds, unsigned char *key, int len )
/*--------------------------------------------------------------------------
   Set an RC4 key an MPEG Audio stream
   Input:  mpds =  mpeg audio stream ptr returned by MPEGDEC_open
           key  =  RC4 key data
           len  =  length of RC4 key data
*/
{
   MPA_STREAM *mps;

   if( !mpds ) return;

   mps = (MPA_STREAM *)mpds->handle;

   if( mps ) {
      mps->keyp = (void *) &MPEGDEC_rc4_key;
      RC4_set_key(mps->keyp, len, key);
   }
} /* MPEGDEC_setkey */

#endif /* USE_RC4 */
