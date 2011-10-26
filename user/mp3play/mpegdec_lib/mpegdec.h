/*------------------------------------------------------------------------------

    File    :   MPEGDEC.H

    Author  :   Stéphane TAVENARD

    $VER:   MPEGDEC.H  1.3  (21/06/1998)

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
    2   |23/04/1997| Library package                                      ST
    3   |24/04/1997| Added MPEGDEC_seek, MPEGDEC_time                     ST
    4   |27/04/1997| Added mono & stereo / freq_max in MPEGDEC_CTRL       ST
    5   |03/05/1997| Added MPEGDEC_ACCESS                                 ST
    6   |07/05/1997| Added stream_size in open, replaced BOOL by INT16    ST
    7   |22/05/1997| Added check_mpeg in MPEGDEC_CTRL                     ST
    7   |22/05/1997| Added bitstream buffer size config in MPEGDEC_CTRL   ST
    7   |22/05/1997| Added MPEGDEC_ERR_xxx                                ST
    8   |06/07/1997| Change int/long to INT32 in MPEGDEC_ACCESS           ST
    8   |06/07/1997| Different settings for Layer I & II and Layer III    ST
    9   |15/07/1997| Added dec_quality                                    ST
    10  |20/09/1997| Added MPEGDEC_find_sync                              ST
    11  |01/11/1997| Added Hooks support (Amiga version)                  ST
    12  |21/06/1998| Added MPEGDEC_scale                                  ST

    ------------------------------------------------------------------------

    MPEG Audio decoder definitions.

------------------------------------------------------------------------------*/

#ifndef MPEGDEC_H
#define MPEGDEC_H

// Controls for decoding

// Qualities
#define MPEGDEC_QUALITY_LOW    0
#define MPEGDEC_QUALITY_MEDIUM 1
#define MPEGDEC_QUALITY_HIGH   2

#include "bitstr.h" // #11

#ifdef HOOKS // #11
/*
   Bitstream Hook function is called like (SAS/C syntax):

   ULONG __saveds __asm HookFunc( register __a0 struct Hook       *hook,
                                  register __a2 APTR               handle,
                                  register __a1 MPEGDEC_ACCESS_PARAM *access );

   MPEGDEC_ACCESS_PARAM struct specify bitstream access function & parameters

   access->func == MPEGDEC_FUNC_OPEN
      open the bitstream
      buffer_size is the i/o block size your read function can use
      stream_size is the total size of the current stream (in bytes, set it to 0 if unknown)
      return your file handle (or NULL if failed)
   access->func == MPEGDEC_FUNC_CLOSE
      close the bitstream
      return 0 if ok
   access->func == MPEGDEC_FUNC_READ
      read bytes from bitstream.
      return # of bytes read or 0 if EOF.
   access->func == MPEGDEC_FUNC_SEEK
      seek to an absolute byte position inside the bitstream
      return 0 if ok
*/

#define MPEGDEC_FUNC_OPEN  0
#define MPEGDEC_FUNC_CLOSE 1
#define MPEGDEC_FUNC_READ  2
#define MPEGDEC_FUNC_SEEK  3

typedef struct {

   LONG  func;           /* MPEGDEC_FUNC_xxx */
   union {
      struct {
         char *stream_name; /* in */
         LONG buffer_size;  /* in */
         LONG stream_size;  /* out */
      } open;
      struct {
         void *buffer;      /* in/out */
         LONG num_bytes;    /* in */
      } read;
      struct {
         LONG abs_byte_seek_pos; /* out */
      } seek;
   } data;

} MPEGDEC_ACCESS_PARAM;

typedef struct Hook MPEGDEC_ACCESS;

#else

// Specify how to access the bitstream
//   open:  open the bitstream, should return your file handle (or NULL if failed)
//          stream_size is the total size of the stream (in bytes, could be 0 if unknown)
//   close: close the bitstream
//   read:  read bytes from bitstream, return # of bytes read or <=0 if EOF
//   seek:  seek to an absolute byte position inside the bitstream, return 0 if Ok

typedef struct { // #5, #8
   INT32 (*open)( char *stream_name, INT32 buffer_size, INT32 *stream_size );
   void (*close)( INT32 handle );
   INT32 (*read)( INT32 handle, void *buffer, INT32 num_bytes );
   int  (*seek)( INT32 handle, INT32 abs_byte_seek_pos );
} MPEGDEC_ACCESS;

#endif

// Decoding output #8
typedef struct {
   INT16 freq_div;       // 1, 2 or 4
   INT16 quality;        // 0 (low) .. 2 (high)
   INT32 freq_max;       // for automatic freq_div (if mono_freq_div == 0)
} MPEGDEC_OUTPUT;

// Decoding layer #8
typedef struct {
   INT16 force_mono;          // 1 to decode stereo stream in mono, 0 otherwise
   MPEGDEC_OUTPUT mono;       // mono settings
   MPEGDEC_OUTPUT stereo;     // stereo settings
} MPEGDEC_LAYER;

// Control structure of MPEG Audio decoding
typedef struct {
   MPEGDEC_ACCESS *bs_access; // NULL for default access (file I/O) or give your own bitstream access
   MPEGDEC_LAYER layer_1_2;   // Layer I & II settings (#8)
   MPEGDEC_LAYER layer_3;     // Layer III settings (#8)
   INT16 check_mpeg;          // 1 to check for mpeg audio validity at start of stream, 0 otherwise
   INT32 stream_buffer_size;  // #7: size of bitstream buffer in bytes (0 -> default size)
                              // NOTE: stream_buffer_size must be multiple of 4 bytes
} MPEGDEC_CTRL;

// Modes
#define MPEGDEC_MODE_STEREO   0
#define MPEGDEC_MODE_J_STEREO 1
#define MPEGDEC_MODE_DUAL     2
#define MPEGDEC_MODE_MONO     3

typedef struct {
   // Stream info
   INT16  norm;         // 1 or 2
   INT16  layer;        // 1..3
   INT16  mode;         // 0..3  (MPEGDEC_MODE_xxx)
   INT16  bitrate;      // in kbps
   INT32  frequency;    // in Hz
   INT16  channels;     // 1 or 2
   UINT32 ms_duration;  // stream duration in ms
   INT16  private_bit;  // 0 or 1
   INT16  copyright;    // 0 or 1
   INT16  original;     // 0 or 1
   // Decoding info according to MPEG control
   INT16  dec_channels;
   INT16  dec_quality;  // #9
   INT32  dec_frequency;
   // Private data
   void  *handle;
} MPEGDEC_STREAM;

#define MPEGDEC_MAX_CHANNELS 2    // Max channels
#define MPEGDEC_PCM_SIZE     1152 // Max samples per frame

// Error codes

#define MPEGDEC_ERR_NONE     0
#define MPEGDEC_ERR_BASE     0
#define MPEGDEC_ERR_EOF      (MPEGDEC_ERR_BASE-1)
#define MPEGDEC_ERR_BADFRAME (MPEGDEC_ERR_BASE-2)
#define MPEGDEC_ERR_MEM      (MPEGDEC_ERR_BASE-3)
#define MPEGDEC_ERR_NO_SYNC  (MPEGDEC_ERR_BASE-4) // #10
#define MPEGDEC_ERR_BADVALUE (MPEGDEC_ERR_BASE-5) // #12

extern MPEGDEC_STREAM *MPEGDEC_open( char *filename, MPEGDEC_CTRL *ctrl );
/*--------------------------------------------------------------------------
   Open an MPEG Audio stream
   Inputs: filename = stream filename to decode
           ctrl = decoding controls
   Return the mpeg audio stream ptr or NULL if failed to open stream
*/

extern void MPEGDEC_close( MPEGDEC_STREAM *mpds );
/*--------------------------------------------------------------------------
   Close an MPEG Audio stream
   Input:  mpds =  mpeg audio stream ptr returned by MPEGDEC_open
*/

extern int MPEGDEC_scale( MPEGDEC_STREAM *mpds, INT32 scale_percent ); // #12
/*--------------------------------------------------------------------------
   Set the output scale for the current stream
   Inputs:  mpds = mpeg audio stream ptr returned by MPEGDEC_open
            scale_percent = scale factor in % to apply to the decoded output
                            100 is the nominal value
   Return 0 if Ok, MPEGDEC_ERR_BADVALUE if invalid scale
*/

extern INT32 MPEGDEC_decode_frame( MPEGDEC_STREAM *mpds,
                                   INT16 *pcm[ MPEGDEC_MAX_CHANNELS ] );
/*--------------------------------------------------------------------------
   Decode the current MPEG Audio frame
   Input:  mpds =  mpeg audio stream ptr returned by MPEGDEC_open
   Output: pcm[] = 16-bit samples
                   pcm[ 0 ] is mono or left voice or channel 1
                   pcm[ 1 ] is right or channel 2
   Return the number of samples or error code:
      MPEGDEC_ERR_EOF if end of stream
      MPEGDEC_ERR_BADFRAME if bad frame

   Note: pcm[]'s be at least arrays of MPEGDEC_PCM_SIZE
         number of samples can be 0 if current frame is skipped, in case
         of error in crc or not enough data for decoding (layer III)
         number of samples = 0 does not indicate end of stream !
*/

extern int MPEGDEC_seek( MPEGDEC_STREAM *mpds, UINT32 ms_time_position );
/*--------------------------------------------------------------------------
   Seek into an MPEG Audio stream
   Inputs:  mpds = mpeg audio stream ptr returned by MPEGDEC_open
            ms_time_position = absolute time position in ms
   Return 0 if Ok, MPEGDEC_ERR_EOF if outside of stream
*/

extern int MPEGDEC_time( MPEGDEC_STREAM *mpds, UINT32 *ms_time_position );
/*--------------------------------------------------------------------------
   Get the current time position of an MPEG Audio stream
   Input:  mpds = mpeg audio stream ptr returned by MPEGDEC_open
   Output: ms_time_position = absolute time position in ms
   Return 0 if Ok
*/

extern INT32 MPEGDEC_find_sync( INT8 *buffer, INT32 buffer_size );
/*--------------------------------------------------------------------------
   Find an mpeg synchronization pattern in a buffer
   This function can be use to check if a file contains MPEG audio stream
   Inputs: buffer = stream buffer to analyze
           buffer_size = need to know top of buffer (must be >= 4)
   Return the the sync position (>=0) or MPEGDEC_ERR_NO_SYNC if not found
*/

#endif /* MPEGDEC_H */
