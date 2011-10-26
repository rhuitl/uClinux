/*------------------------------------------------------------------------------

    File    :   HUFF.h

    Author  :   Stéphane TAVENARD

    $VER:   HUFF.h  0.3  (04/07/1997)

    (C) Copyright 1997-1997 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |17/03/1997| Initial revision                                     ST
    1   |31/03/1997| First aminet release                                 ST
    2   |07/06/1997| Added HUFF_fill_bytes                                ST
    3   |04/07/1997| Fix bug in HUFF_pos & HUFF_read_bits                 ST

    ------------------------------------------------------------------------

    Definition of Huffman Codes handling

------------------------------------------------------------------------------*/

#ifndef HUFF_H
#define HUFF_H

#include <stdio.h>

#define HUFF_BUFFER_SIZE 4096

typedef struct {
   int buffer_size;
   unsigned char *buffer;
   int write_index;
   int read_index;
   unsigned long bit_cache;
   int cache_size;
   unsigned long bits;
   INT16 nul_begin; // begin of last null zone
} HUFFMAN;

#define HUFF_MAX_BITS   32

extern void HUFF_close( HUFFMAN *h );
extern HUFFMAN *HUFF_open( void );

extern int HUFF_reset( HUFFMAN *h );
/*---------------------------------
   Reset an huffman stream
*/

// #3
#define HUFF_pos( h ) (((h->read_index<<3) - h->cache_size)<0)?\
                       (((h->read_index<<3) - h->cache_size)+(HUFF_BUFFER_SIZE<<3)):\
                       ((h->read_index<<3) - h->cache_size)
#define HUFF_diff( start, stop ) (start <= stop)?(stop-start):((HUFF_BUFFER_SIZE<<3)+stop-start)

#define HUFF_fill_byte( h, b ) ( h->buffer[ h->write_index++ ] = b,\
                                 h->write_index &= HUFF_BUFFER_SIZE-1 )

extern void HUFF_fill_bytes( HUFFMAN *h, unsigned int count, char *buffer );
/*-------------------------------------------------------------------------
   Write bytes to huffman buffer (#2)
*/

extern int HUFF_set_start( HUFFMAN *h, int start_pos );
extern int HUFF_seek( HUFFMAN *h, int seek_pos );

extern unsigned long HUFF_read_bit_cache( HUFFMAN *h );
extern unsigned long HUFF_read_bits_cache( HUFFMAN *h, unsigned int count );

#define HUFF_read_bit( h ) ((h->cache_size-- > 0) ? \
                            (h->bits = (h->bit_cache & 0x80000000)?1:0,\
                             h->bit_cache <<= 1, h->bits) :\
                            HUFF_read_bit_cache( h ))

#define HUFF_read_bits( h, c ) (((c)<=0)?0:(h->cache_size >= (c)) ? \
                                (h->cache_size -= (c), h->bits = h->bit_cache >> (32-(c)),\
                                 h->bit_cache <<= (c), h->bits) :\
                                HUFF_read_bits_cache( h, c ))

extern int HUFF_decode_pair( HUFFMAN *h, INT16 table, INT16 count, INT16 *x );

extern int HUFF_decode_quad( HUFFMAN *h, INT16 table, INT16 max_bits,
                             INT16 val_count, INT16 val_top, INT16 *x );

#endif /* HUFF_H */
