/*------------------------------------------------------------------------------

    File    :   MPEGDEC_demo.c

    Author  :   Stéphane TAVENARD

    $VER:   MPEGDEC_demo.c 0.3  (20/08/1997)

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
    0   |07/05/1997| Initial revision                                     ST
    1   |07/05/1997| Released                                             ST
    2   |23/05/1997| Stream buffer is now configurable                    ST
    3   |20/08/1997| Update to V0.9 OF MPEGDEC library                    ST

    ------------------------------------------------------------------------

    Demo of how to use MPEGDEC link library with SAS/C compiler
    Use of private bitstream access functions (access to ram buffer)

------------------------------------------------------------------------------*/

#include "defs.h"
#include "mpegdec.h"

//#include <dos.h>

static char *Version = "$VER:MPEGDEC_demo 0.3 (20.8.97) (C)1997 Stéphane TAVENARD";

static MPEGDEC_STREAM *mps = NULL;

// Ram buffer
//#define MPEGA_BUFFER_SIZE  (256*1024) // in bytes
#define MPEGA_BUFFER_SIZE  (64*1024) // in bytes
static INT8   *mpega_buffer = NULL;
static UINT32  mpega_buffer_offset = 0;
static UINT32  mpega_buffer_size = 0;

static int break_cleanup( void )
{
   if( mps ) {
      MPEGDEC_close( mps );
      mps = NULL;
   }
   return 1;
}

static void exit_cleanup( void )
{
   (void)break_cleanup();
}

// Here start our own bitstream access routines

INT32 bs_open( char *stream_name, INT32 buffer_size, INT32 *stream_size )
/*-----------------------------------------------------------------------
*/
{
   // We don't really need stream_name
   // print it anyway...
   // buffer_size indicate the following read access size

   printf( "bs_open: '%s'\n", stream_name );

   // Some open errors...
   if( !mpega_buffer ) return NULL;

   // initialize some variables
   mpega_buffer_offset = 0;

   // We know total size, we can set it
   *stream_size = mpega_buffer_size;

   // Just return a dummy handle (not NULL)
   return 1;
}

void bs_close( INT32 handle )
/*---------------------------
*/
{
   if( handle ) {
      // Clean up
      printf( "bs_close\n" );
   }
}

INT32 bs_read( INT32 handle, void *buffer, INT32 num_bytes )
/*----------------------------------------------------------
*/
{

   INT32 read_size;

   if( !handle ) return -1; // Check valid handle

   read_size = mpega_buffer_size - mpega_buffer_offset;
   if( read_size > num_bytes ) read_size = num_bytes;

   if( read_size > 0 ) {
      if( !buffer ) return -1;
      // Fill buffer with our MPEG audio data
      memcpy( buffer, &mpega_buffer[ mpega_buffer_offset ], read_size );
      mpega_buffer_offset += read_size;
   }
   else {
      read_size = -1; // End of stream
   }

   return read_size;
}

int bs_seek( INT32 handle, INT32 abs_byte_seek_pos )
/*-----------------------------------------------
*/
{
   if( !handle ) return -1;

   if( abs_byte_seek_pos <= 0 ) mpega_buffer_offset = 0;
   else if( abs_byte_seek_pos >= mpega_buffer_size ) return -1;
   else mpega_buffer_offset = abs_byte_seek_pos;
   return 0;
}

int output_pcm( INT16 channels, INT16*pcm[ 2 ], INT32 count, FILE *out_file )
/*---------------------------------------------------------------------------
   Ouput the current decoded PCM to a file
   Return 0 if Ok
*/
{
#define PCM_BUFFER_SIZE (MPEGDEC_MAX_CHANNELS*MPEGDEC_PCM_SIZE)
   static INT16 *pcm_buffer = NULL;
   if( !out_file ) return -1;

   if( !pcm_buffer ) {
      pcm_buffer = (INT16 *)malloc( PCM_BUFFER_SIZE * sizeof(INT16) );
      if( !pcm_buffer ) return -1;
   }
   if( channels == 2 ) {
      register INT16 *pcm0, *pcm1, *pcmLR;
      register INT32 i;

      pcm0 = pcm[ 0 ];
      pcm1 = pcm[ 1 ];
      pcmLR = pcm_buffer;
      i = count;
      while( i-- ) {
         *pcmLR++ = *pcm0++;
         *pcmLR++ = *pcm1++;
      }
      fwrite( pcm_buffer, 4, count, out_file );
   }
   else {
      fwrite( pcm[ 0 ], 2, count, out_file );
   }

   return 0;

} /* output_pcm */

int main( int argc, char **argv )
{
   char *in_filename;
   FILE *in_file;
   int frame = 0;
   char *out_filename = NULL;
   FILE *out_file = NULL;
   INT16 i;
   INT32 pcm_count;
   INT16 *pcm[ MPEGDEC_MAX_CHANNELS ];

   static char *modes[] = { "stereo", "j-stereo", "dual", "mono" };

   MPEGDEC_ACCESS bs_access = { bs_open, bs_close, bs_read, bs_seek };

   MPEGDEC_CTRL mpa_ctrl = {
      NULL,    // Bitstream access is default file I/O
      // Layers I & II settings (#3)
      { FALSE, { 1, 2, 48000 }, { 1, 2, 48000 } },
      // Layer III settings (#3)
      { FALSE, { 1, 2, 48000 }, { 1, 2, 48000 } },
      0,           // #2: Don't check mpeg validity at start (needed for mux stream)
      2048         // #2: Stream Buffer size
   };

   //   onbreak( break_cleanup );
   //  atexit( exit_cleanup );

   if( argc <= 1 ) {
      fprintf( stderr, "%s\n", &Version[ 5 ] );
      fprintf( stderr, "Usage %s <input mpeg audio file> [<output pcm file>]\n", argv[ 0 ] );
      fprintf( stderr, "This is a demo of how to use MPEGDEC library\n" );
      exit( 0 );
   }

   in_filename = argv[ 1 ];
   if( argc > 2 ) out_filename = argv[ 2 ];

   mpega_buffer = (INT8 *)malloc( MPEGA_BUFFER_SIZE );
   if( !mpega_buffer ) {
      fprintf( stderr, "Can't allocate MPEG buffer\n" );
      exit( 0 );
   }

   for( i=0; i<MPEGDEC_MAX_CHANNELS; i++ ) {
      pcm[ i ] = malloc( MPEGDEC_PCM_SIZE * sizeof( INT16 ) );
      if( !pcm[ i ] ) {
         fprintf( stderr, "Can't allocate PCM buffers\n" );
         exit( 0 );
      }
   }

   // Open the output file
   if( out_filename ) {
      out_file = fopen( out_filename, "wb" );
      if( !out_file ) {
         fprintf( stderr, "Can't open output file '%s'\n", out_filename );
         exit( 0 );
      }
   }

   // Load the stream into a ram buffer
   in_file = fopen( in_filename, "rb" );
   if( !in_file ) {
      fprintf( stderr, "Unable to open file '%s'\n", in_filename );
      exit( 0 );
   }
   mpega_buffer_size = fread( mpega_buffer, 1, MPEGA_BUFFER_SIZE, in_file );
   fclose( in_file );

   // Set our bitstream access routines and open the stream
   mpa_ctrl.bs_access = &bs_access;

   mps = MPEGDEC_open( in_filename, &mpa_ctrl );
   if( !mps ) {
      printf( "Unable to open MPEG Audio stream '%s'\n", in_filename );
      exit( 0 );
   }

   printf( "MPEG%d-%s %s %dkbps %dHz (%ld ms)\n",
           mps->norm, (mps->layer == 1)?"I":(mps->layer == 2)?"II":"III",
           modes[ mps->mode ], mps->bitrate, mps->frequency, mps->ms_duration );

   printf( "Decoding: Channels=%d Quality=%d Frequency=%dHz\n",
            mps->dec_channels, mps->dec_quality, mps->dec_frequency ); // #3

   while( (pcm_count = MPEGDEC_decode_frame( mps, pcm )) >= 0 ) {
      if( out_file ) output_pcm( mps->dec_channels, pcm, pcm_count, out_file );
      frame++;
      fprintf( stderr, "{%04d}\r", frame ); fflush( stderr );
   }
   fprintf( stderr, "\n" );

   MPEGDEC_close( mps );
   mps = NULL;
}

