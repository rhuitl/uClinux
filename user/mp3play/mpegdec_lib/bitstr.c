/*------------------------------------------------------------------------------

    File    :   BITSTR.c

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
    0   |21/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |19/04/1997| Added async I/O                                      ST
    3   |03/05/1997| Added file access spec                               ST
    4   |07/05/1997| Added stream_size in stream access spec              ST
    5   |07/06/1997| Added BSTR_read_bytes                                ST
    6   |04/07/1997| Added stream size calc with fseek & ftell            ST
    7   |19/07/1997| Change BSTR_seek error handling & defaut Amiga I/O   ST
    8   |01/11/1997| Added Hooks support (for AMIGA Version)              ST
    9   |02/05/1998| Added PPC support (for AMIGA Version)                ST
    10  |16/06/1998| Added BSTR_pos() function                            ST
    11  |23/06/1998| Optimized ppc cache                                  ST

    ------------------------------------------------------------------------

    BitStream files handling
    Pure C Version

------------------------------------------------------------------------------*/

#include "defs.h" // #8
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bitstr.h"

#ifdef AMIGA // #7
#include <dos/stdio.h>
#include <proto/dos.h>
#ifdef HOOKS
#endif
#endif

/* Default file I/O functions (#3) */

static long def_open( char *stream_name, long buffer_size, long *stream_size )
/*----------------------------------------------------------------------------
*/
{

#ifdef PPC // #9 Begin
   BPTR file_ptr;

   *stream_size = 0;
   file_ptr = PPCOpen( stream_name, MODE_OLDFILE );
/*
   if( (file_ptr) && (buffer_size > 0) ) {
      SetVBuf( file_ptr, NULL, BUF_FULL, buffer_size );
   }
*/
   *stream_size = 0;
   if( file_ptr ) {
       if( PPCSeek( file_ptr, 0, OFFSET_END ) != -1 ) {
          *stream_size = PPCSeek( file_ptr, 0, OFFSET_CURRENT );
          PPCSeek( file_ptr, 0, OFFSET_BEGINNING );
       }
   }
#else

#ifdef AMIGA // #7
   BPTR file_ptr;

   *stream_size = 0;
   file_ptr = Open( stream_name, MODE_OLDFILE );
   if( (file_ptr) && (buffer_size > 0) ) {
      SetVBuf( file_ptr, NULL, BUF_FULL, buffer_size );
   }

   *stream_size = 0;
   if( file_ptr ) {
       if( Seek( file_ptr, 0, OFFSET_END ) != -1 ) {
          *stream_size = Seek( file_ptr, 0, OFFSET_CURRENT );
          Seek( file_ptr, 0, OFFSET_BEGINNING );
       }
   }

#else

   FILE *file_ptr;

   file_ptr = fopen( stream_name, "rb" );
   if( (file_ptr) && (buffer_size > 0 ) ) {
      setvbuf( file_ptr, NULL, _IOFBF, buffer_size );
   }

   *stream_size = 0;
   if( file_ptr ) { // #6
       if( !fseek( file_ptr, 0, SEEK_END ) ) {
          *stream_size = ftell( file_ptr );
          fseek( file_ptr, 0, SEEK_SET );
       }
   }
#endif
#endif // #9 End

   return (long)file_ptr;
}

static void def_close( long handle )
/*----------------------------------
*/
{
#ifdef PPC // #9 Begin
   if( handle ) PPCClose( (BPTR)handle );
#else
#ifdef AMIGA // #7
   if( handle ) Close( (BPTR)handle );
#else
   if( handle ) fclose( (FILE *)handle );
#endif
#endif // #9 End
}

static long def_read( long handle, void *buffer, long num_bytes )
/*---------------------------------------------------------------
*/
{
   long read_size = -1;

#ifdef PPC // #9 Begin
   if( handle ) {
      read_size = PPCRead( (BPTR)handle, buffer, num_bytes );
   }
#else
#ifdef AMIGA // #7
   if( handle ) {
      read_size = FRead( (BPTR)handle, buffer, 1, num_bytes );
   }
#else
   if( handle ) {
      read_size = fread( buffer, 1, num_bytes, (FILE *)handle );
   }
#endif
#endif // #9 End

   return read_size;
}

static int def_seek( long handle, long abs_byte_seek_pos )
/*--------------------------------------------------------
*/
{
   int err = 0;

#ifdef PPC // #9 Begin
   if( handle ) {
      if( PPCSeek( (BPTR)handle, abs_byte_seek_pos, OFFSET_BEGINNING ) == -1 ) err = -1;
   }
#else
#ifdef AMIGA // #7
   if( handle ) {
      if( Seek( (BPTR)handle, abs_byte_seek_pos, OFFSET_BEGINNING ) == -1 ) err = -1;
   }
#else
   if( handle ) {
      err = fseek( (FILE *)handle, abs_byte_seek_pos, SEEK_SET );
   }
#endif
#endif // #9 End

   return err;
}

#ifdef HOOKS // #8

#ifdef PPC // #9 Begin
static ULONG ppc_call_hook( BITSTREAM *bs, APTR handle, BSTR_ACCESS_PARAM *access ) {

   if( !bs->caos ) {
      bs->caos = (struct Caos *)PPCAllocVec( sizeof(struct Caos), MEMF_PUBLIC | MEMF_CLEAR );
      if( !bs->caos ) return -1;
   }

   bs->caos->caos_Un.Function = (APTR)bs->baccess.h_Entry;
   bs->caos->M68kCacheMode = IF_CACHEFLUSHALL;
   bs->caos->PPCCacheMode = IF_CACHEFLUSHALL;
//   bs->caos->M68kCacheMode = IF_CACHEFLUSHNO;
//   bs->caos->PPCCacheMode = IF_CACHEFLUSHNO;
   bs->caos->a0 = (ULONG)&bs->baccess;
   bs->caos->a2 = (ULONG)handle;
   bs->caos->a1 = (ULONG)access;
   bs->caos->d0 = 0;
   (void)PPCCallM68k( bs->caos );
   return bs->caos->d0;
}

#else
static ULONG SAVEDS ASM def_baccess( REG(a0) struct Hook       *hook,
                                     REG(a2) APTR               handle,
                                     REG(a1) BSTR_ACCESS_PARAM *access ) {
/*-----------------------------------------------------------------------
*/

   switch( access->func ) {

      case BSTR_FUNC_OPEN:
         return (ULONG)def_open( access->data.open.stream_name,
                                 access->data.open.buffer_size,
                                 &access->data.open.stream_size );
      case BSTR_FUNC_CLOSE:
         def_close( (long)handle );
         break;
      case BSTR_FUNC_READ:
         return (ULONG)def_read( (long)handle, access->data.read.buffer,
                                 access->data.read.num_bytes );
      case BSTR_FUNC_SEEK:
         return (ULONG)def_seek( (long)handle, access->data.seek.abs_byte_seek_pos );
   }
   return 0;
}

typedef ULONG ASM (*BSTR_HOOK_FUNC)( REG(a0) struct Hook       *hook,
                                     REG(a2) APTR               handle,
                                     REG(a1) BSTR_ACCESS_PARAM *access );
#endif // #9 End

#endif

/* End of default file I/O functions */

void BSTR_close( BITSTREAM *bitstream )
{
   if( bitstream ) {
      if( bitstream->buffer ) {
         free( bitstream->buffer );
      }
      if( bitstream->file_handle ) { // #3
#ifdef HOOKS // #8
         BSTR_ACCESS_PARAM param;

         param.func = BSTR_FUNC_CLOSE;

#ifdef PPC // #9 Begin
         ppc_call_hook( bitstream, (APTR)bitstream->file_handle, &param );
#else
//         CallHookPkt( &bitstream->baccess, (APTR)bitstream->file_handle, &param );
         ((BSTR_HOOK_FUNC)bitstream->baccess.h_Entry)( &bitstream->baccess, (APTR)bitstream->file_handle, &param );
#endif // #9 End

#else
         if( bitstream->baccess.close ) {
            bitstream->baccess.close( bitstream->file_handle );
         }
#endif
      }

#ifdef PPC // #9
      if( bitstream->caos ) {
         PPCFreeVec( bitstream->caos );
         bitstream->caos = NULL;
      }
#endif
      free( bitstream );
   }
}

BITSTREAM *BSTR_open( BITSTREAM_ACCESS *bs_access, char *filename, long buffer_size )
/*-----------------------------------------------------------------------------------
   Open a BitStream for read
   Inputs:
      bs_access = specify how to access to the bitstream (functions)
               if NULL, use standard file i/o
      filename = name of the bitstream
      buffer_size = # of bytes read for each access
*/
{
   BITSTREAM *bs;

   bs = (BITSTREAM *)malloc( sizeof( BITSTREAM ) );
   if( !bs ) return NULL;
   memset( bs, 0, sizeof( BITSTREAM ) );
#ifdef HOOKS // #8
   if( bs_access ) {
      bs->baccess = *bs_access;
   }
   else {
#ifdef PPC // #9
      // We always need a M68k Hook function
      free( bs );
      return NULL;
#else
      bs->baccess.h_Entry = (HOOKFUNC)def_baccess;
#endif
   }

#else
   if( bs_access ) { // #3
      bs->baccess = *bs_access;
   }
   else {
      bs->baccess.open = def_open;
      bs->baccess.close = def_close;
      bs->baccess.read = def_read;
      bs->baccess.seek = def_seek;
   }
#endif
   // Buffer size must be 4-bytes aligned
   buffer_size &= ~3;

#ifdef PPC // #9
   // Mark as non cachable memory area because shared by M68k & PPC
//   bs->buffer = PPCAllocVec( buffer_size, MEMF_PUBLIC | MEMF_CLEAR | MEMF_NOCACHESYNCPPC | MEMF_NOCACHESYNCM68K ); // #11 Old
   bs->buffer = PPCAllocVec( buffer_size, MEMF_PUBLIC | MEMF_CLEAR ); // #11 Cached
//   bs->buffer = malloc( buffer_size );
#else
   bs->buffer = malloc( buffer_size );
#endif
   if( !bs->buffer ) {
      BSTR_close( bs );
      return NULL;
   }
   bs->buffer_size = buffer_size;

#ifdef HOOKS // #8
   {
      BSTR_ACCESS_PARAM param;

      param.func = BSTR_FUNC_OPEN;
      param.data.open.stream_name = filename;
      param.data.open.buffer_size = buffer_size;
      param.data.open.stream_size = 0;

#ifdef PPC // #9 Begin
      bs->file_handle = ppc_call_hook( bs, NULL, &param );
#else
//      bs->file_handle = CallHookPkt( &bs->baccess, NULL, &param );
      bs->file_handle = ((BSTR_HOOK_FUNC)bs->baccess.h_Entry)( &bs->baccess, NULL, &param );
#endif // #9 End
      bs->bitstream_size = param.data.open.stream_size;
   }
#else
   if( !bs->baccess.open ) { // #3
      BSTR_close( bs );
      return NULL;
   }
   bs->file_handle = bs->baccess.open( filename, buffer_size, &bs->bitstream_size );
#endif

   if( !bs->file_handle ) {
      BSTR_close( bs );
      return NULL;
   }
//   (void)BSTR_seek( bs, 0 );

   bs->buffer_ptr = bs->buffer; // #10
   bs->buffer_len = 0; // #10
   bs->buffer_pos = 0; // #10

   return bs;
}

static int fill_buffer( BITSTREAM *bitstream )
{
#ifdef BSTR_MSBF
   bitstream->buffer[ 0 ] = 0;
#else
   bitstream->buffer[ 1 ] = bitstream->buffer[ 2 ] = bitstream->buffer[ 3 ] = 0;
#endif

   if( bitstream->end_of_stream ) return 1; // #3

#ifdef HOOKS // #8
   {
      BSTR_ACCESS_PARAM param;

      param.func = BSTR_FUNC_READ;
      param.data.read.buffer = bitstream->buffer;
      param.data.read.num_bytes = bitstream->buffer_size;
#ifdef PPC // #9 Begin
      PPCCacheFlush( bitstream->buffer, bitstream->buffer_size ); // #11
      bitstream->remain_bytes = ppc_call_hook( bitstream, (APTR)bitstream->file_handle, &param );
#else
//      bitstream->remain_bytes = CallHookPkt( &bitstream->baccess, (APTR)bitstream->file_handle, &param );
      bitstream->remain_bytes = ((BSTR_HOOK_FUNC)bitstream->baccess.h_Entry)( &bitstream->baccess, (APTR)bitstream->file_handle, &param );
#endif // #9 End
   }
#else
   if( !bitstream->baccess.read ) return 1; // #3

   bitstream->remain_bytes = bitstream->baccess.read( bitstream->file_handle,
                                                      bitstream->buffer,
                                                      bitstream->buffer_size ); // #3
#endif

   bitstream->buffer_len = bitstream->remain_bytes; // #10
   bitstream->buffer_pos += (long)bitstream->buffer_ptr - (long)bitstream->buffer; // #10

   bitstream->buffer_ptr = bitstream->buffer;
   bitstream->cache_size = 0;

   if( bitstream->remain_bytes <= 0 ) {
      bitstream->end_of_stream = 1;
      return 1; /* empty */
   }
   else if( bitstream->remain_bytes < 4 ) {
      bitstream->remain_bytes = 4;
   }

   return 0;

} /* fill_buffer */


#ifdef BSTR_MSBF
#define FILL_CACHE( b ) { if( b->remain_bytes <= 0 ) fill_buffer( b ); b->remain_bytes -= 4;\
                          b->bit_cache = *b->buffer_ptr++; }
#else
#define FILL_CACHE( b ) { if( b->remain_bytes <= 0 ) fill_buffer( b ); b->remain_bytes -= 4;\
   b->bit_cache = (((unsigned long)b->buffer_ptr[0])<<24) |\
                  (((unsigned long)b->buffer_ptr[1])<<16)|\
                                  (((unsigned long)b->buffer_ptr[2])<<8) |\
                                  ((unsigned long)b->buffer_ptr[3]); b->buffer_ptr+=4;\
   }
#endif


int BSTR_seek( BITSTREAM *bitstream, long seek_byte_pos )
{
   int err;

   // #10 Begin
   // Optimize seek if inside current buffer
   long offset_pos = seek_byte_pos - bitstream->buffer_pos;

   if( bitstream->buffer_len > 0 ) {
      if( (offset_pos >= 0) && (offset_pos < bitstream->buffer_len) ) {
         // Use current buffer
         long remain = offset_pos & 3; // Remainder
         offset_pos &= ~3; // align to 32 bit
         bitstream->remain_bytes = bitstream->buffer_len - offset_pos;
#ifdef BSTR_MSBF
         bitstream->buffer_ptr = bitstream->buffer + (offset_pos>>2);
#else
         bitstream->buffer_ptr = bitstream->buffer + offset_pos;
#endif
         bitstream->cache_size = 0;
         bitstream->bits = 0;
         FILL_CACHE( bitstream );
         bitstream->cache_size = 32;
         // Skip remainder
         while( remain-- ) (void)BSTR_read_byte( bitstream );
         return 0;
      }
   }
   // #10 End
#ifdef HOOKS // #8
   {
      BSTR_ACCESS_PARAM param;

      param.func = BSTR_FUNC_SEEK;
      param.data.seek.abs_byte_seek_pos = seek_byte_pos;
#ifdef PPC // #9 Begin
      err = ppc_call_hook( bitstream, (APTR)bitstream->file_handle, &param );
#else
//      err = (int)CallHookPkt( &bitstream->baccess, (APTR)bitstream->file_handle, &param );
      err = (int)((BSTR_HOOK_FUNC)bitstream->baccess.h_Entry)( &bitstream->baccess, (APTR)bitstream->file_handle, &param );
#endif // #9 End
      if( err ) return err;
   }
#else
   if( bitstream->baccess.seek ) {
      err = bitstream->baccess.seek( bitstream->file_handle, seek_byte_pos );
      if( err ) return err; // #7
   }
#endif
   bitstream->remain_bytes = 0;
   bitstream->buffer_ptr = bitstream->buffer;
   bitstream->end_of_stream = 0;
   bitstream->cache_size = 0;
   bitstream->bits = 0;
   bitstream->buffer_len = 0; // #10
   bitstream->buffer_pos = seek_byte_pos; // #10
   return 0;
}


/* #10 Begin */
long BSTR_pos( BITSTREAM *bitstream ) {

   return bitstream->buffer_pos + (long)bitstream->buffer_ptr - (long)bitstream->buffer
          - (bitstream->cache_size >> 3);
}
/* #10 End */

unsigned long BSTR_read_byte( BITSTREAM *b )
{
   if( b->cache_size < 8 ) {
      FILL_CACHE( b );
      b->cache_size = 32;
   }
   if( b->cache_size & 7 ) { // Not aligned
      b->bit_cache <<= b->cache_size & 7;
      b->cache_size &= ~7;
   }

   b->bits = b->bit_cache >> 24;
   b->bit_cache <<= 8;
   b->cache_size -= 8;
   return b->bits;
}

unsigned int BSTR_read_bytes( BITSTREAM *b, unsigned int count, char *buffer )
{
   if( count == 0 ) return 0;

   if( b->cache_size & 7 ) { // Not aligned
      b->bit_cache <<= b->cache_size & 7;
      b->cache_size &= ~7;
   }
   while( (b->cache_size > 0) && (count-- > 0 ) ) {
      *buffer++ = b->bit_cache >> 24;
      b->bit_cache <<= 8;
      b->cache_size -= 8;
   }
   while( count > 3 ) {
      register int to_fill;

      if( b->remain_bytes <= 0 ) {
         if( fill_buffer( b ) ) return 0;
      }
      to_fill = count & ~3; // Important 4-bytes aligned
      // Note: b->remain_bytes is always 4-bytes aligned
      if( to_fill > b->remain_bytes ) to_fill = b->remain_bytes;

      memcpy( buffer, b->buffer_ptr, to_fill );
      count -= to_fill;
      buffer += to_fill;
      b->remain_bytes -= to_fill;
#ifdef BSTR_MSBF
      b->buffer_ptr += to_fill>>2; // This is a INT32 pointer here.
#else
      b->buffer_ptr += to_fill;
#endif
   }

   // Not 4 bytes aligned -> use cached read
   while( count > 0 ) {
      *buffer++ = BSTR_read_byte( b );
      count--;
   }

   b->bits = (unsigned int)*(buffer-1);
   return 1;
}

unsigned long BSTR_read_bit_cache( BITSTREAM *b )
{
   register unsigned long bits;

   FILL_CACHE( b );

   b->cache_size = 31;

   bits = (b->bit_cache & 0x80000000)?1:0;
   b->bit_cache <<= 1;

   return bits;
}

unsigned long BSTR_read_bits_cache( BITSTREAM *b, unsigned int count )
{
   register unsigned long bits;

   bits = b->bit_cache >> (32 - count);
   count -= b->cache_size;

   FILL_CACHE( b );
   b->cache_size = 32 - count;

   bits |= b->bit_cache >> (32 - count);
   b->bit_cache <<= count;

   return bits;
}

