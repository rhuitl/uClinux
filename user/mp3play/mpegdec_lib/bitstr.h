/*------------------------------------------------------------------------------

    File    :   BITSTR.h

    Author  :   Stéphane TAVENARD

    (C) Copyright 1997-1998 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |21/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |19/04/1997| Added async I/O                                      ST
    3   |03/05/1997| Added stream access spec (& suppressed async I/O)    ST
    4   |07/05/1997| Added stream_size in stream access spec              ST
    5   |07/06/1997| Added BSTR_read_bytes                                ST
    6   |11/07/1997| Added LITTLE_ENDIAN define                           ST
    7   |01/11/1997| Added Hooks support (for AMIGA Version)              ST
    8   |02/05/1998| Added PPC support (for AMIGA Version)                ST
    9   |16/06/1998| Added BSTR_pos() function                            ST

    ------------------------------------------------------------------------

    C Definition of BitStream files handling
    Pure C Version

------------------------------------------------------------------------------*/

#ifndef BITSTR_H
#define BITSTR_H

#ifdef PPC // #8
//#define BSTR_MSBF
#else
#ifndef LITTLE_ENDIAN // #6
#define BSTR_MSBF
#endif
#endif

#ifdef BSTR_MSBF // This target is MSB first, so faster
#define BSTR_BUFF unsigned int
#else
#define BSTR_BUFF unsigned char
#endif

#include <stdio.h>

#ifdef LIBRARY // #8
#define HOOKS
#include <utility/hooks.h>
#endif

#ifdef AMIGA // #7
#define HOOKS
#include <utility/hooks.h>
#endif

#ifdef HOOKS // #7
/*
   Bitstream Hook function is called like (SAS/C syntax):

   ULONG __saveds __asm HookFunc( register __a0 struct Hook       *hook,
                                  register __a2 APTR               handle,
                                  register __a1 BSTR_ACCESS_PARAM *access );

   BSTR_ACCESS_PARAM struct specify bitstream access function & parameters

   access->func == BSTR_FUNC_OPEN
      open the bitstream
      buffer_size is the i/o block size your read function can use
      stream_size is the total size of the current stream (in bytes, set it to 0 if unknown)
      return your file handle (or NULL if failed)
   access->func == BSTR_FUNC_CLOSE
      close the bitstream
      return 0 if ok
   access->func == BSTR_FUNC_READ
      read bytes from bitstream.
      return # of bytes read or 0 if EOF.
   access->func == BSTR_FUNC_SEEK
      seek to an absolute byte position inside the bitstream
      return 0 if ok
*/

#define BSTR_FUNC_OPEN  0
#define BSTR_FUNC_CLOSE 1
#define BSTR_FUNC_READ  2
#define BSTR_FUNC_SEEK  3

typedef struct {

   LONG  func;           /* BSTR_FUNC_xxx */
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

} BSTR_ACCESS_PARAM;

typedef struct Hook BITSTREAM_ACCESS;

#else

/* File stream access (#3)
   open:  open the bitstream, should return the file handle or NULL if failed)
          stream_size is the total size of the stream (in bytes, could be 0 if unknown)
   close: close the bitstream
   read:  read bytes from bitstream, return # of bytes read or <=0 if EOF
   seek:  seek to an absolute byte position inside the bitstream, return 0 if Ok
*/

typedef struct { // #3
   long  (*open)( char *stream_name, long buffer_size, long *stream_size );
   void (*close)( long handle );
   long (*read)( long handle, void *buffer, long num_bytes );
   int  (*seek)( long handle, long abs_byte_seek_pos );
} BITSTREAM_ACCESS;

#endif

typedef struct {
   BITSTREAM_ACCESS baccess; // #3
   long file_handle;         // #3
   long buffer_size;
   BSTR_BUFF *buffer;
   BSTR_BUFF *buffer_ptr;
   long remain_bytes;
   long bitstream_size;
   int end_of_stream;
   unsigned int bit_cache;
   int cache_size;
   unsigned int bits;
   long buffer_len; // #9
   long buffer_pos; // #9
#ifdef PPC // #8
   struct Caos *caos;
#endif
} BITSTREAM;

#define BSTR_MAX_BITS 32

extern BITSTREAM *BSTR_open( BITSTREAM_ACCESS *bs_access, char *filename, long buffer_size );
/*------------------------------------------------------------------------------------------
   Open a BitStream for read
   Inputs:
      bs_access = specify how to access to the bitstream (functions)
               if NULL, use standard file i/o
      filename = name of the bitstream
      buffer_size = # of bytes read for each access
*/

extern void BSTR_close( BITSTREAM *bitstream );

extern int BSTR_seek( BITSTREAM *bitstream, long seek_byte_pos );

extern long BSTR_pos( BITSTREAM *bitstream ); // #9

#define BSTR_end( b ) b->end_of_stream

extern unsigned long BSTR_read_byte( BITSTREAM *b );
extern unsigned int BSTR_read_bytes( BITSTREAM *b, unsigned int count, char *buffer ); // #5

extern unsigned long BSTR_read_bit_cache( BITSTREAM *bitstream );
extern unsigned long BSTR_read_bits_cache( BITSTREAM *bitstream, unsigned int bit_count );

#define BSTR_read_bit( b ) ((b->cache_size-- > 0) ? \
                            (b->bits = (b->bit_cache & 0x80000000)?1:0,\
                            b->bit_cache <<= 1, b->bits) :\
                            BSTR_read_bit_cache( b ))

#define BSTR_read_bits( b, c ) ((b->cache_size >= (c)) ? \
                                (b->cache_size -= c, b->bits = b->bit_cache >> (32-(c)),\
                                 b->bit_cache <<= c, b->bits) :\
                                 BSTR_read_bits_cache( b, c ))

#endif
