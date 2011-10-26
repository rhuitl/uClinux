/*------------------------------------------------------------------------------

    File    :   MPEGTAB.H

    Author  :   Stéphane TAVENARD

    $VER:   MPEGTAB.H  0.1  (31/03/1997)

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
    0   |19/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST

    ------------------------------------------------------------------------

    MPEG Audio tables references

------------------------------------------------------------------------------*/

#ifndef MPEGTAB_H
#define MPEGTAB_H

typedef struct {
   UINT16 treelen;
   UINT16 xlen;
   UINT16 ylen;
   UINT16 linbits;
   UINT16 linmax;
   const unsigned char (*val)[2];
} MPT_HUFF;

#ifdef MPEGAUD_INT
#define MPEGTAB_MULT_TYPE INT32
#define MPEGTAB_MULT_BITS 15
#define MPEGTAB_DEW_TYPE INT16
#define MPEGTAB_DEW_BITS 14
#define MPEGTAB_POW_TYPE INT32
#define MPEGTAB_POW_BITS 18
extern FAR const MPEGTAB_POW_TYPE MPT_pow_4_3[ 8192 ];
#else
#define MPEGTAB_MULT_TYPE REAL
#define MPEGTAB_DEW_TYPE REAL
#endif

extern const MPEGTAB_MULT_TYPE MPT_multiple[ 64 ];
extern const MPEGTAB_DEW_TYPE MPT_dewindow[ 512 ];

extern const UINT16 MPT_freq[ 2 ][ 4 ];
extern const INT16 MPT_bitrate[ 2 ][ 3 ][ 16 ];
extern const INT16 MPT_sblimit[ 5 ];
extern const INT16 MPT_jsbound[ 3 ][ 4 ];

// MPEG-II Alloc tables
extern const UINT8 MPT_alloc_0[][ 16 ];
extern const UINT8 MPT_alloc_1[][ 16 ];
extern const UINT8 MPT_alloc_2[][ 16 ];
extern const UINT8 MPT_alloc_3[][ 16 ];
extern const UINT8 MPT_alloc_4[][ 16 ];

#endif /* MPEGTAB_H */
