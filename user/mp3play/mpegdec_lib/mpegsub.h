/*------------------------------------------------------------------------------

    File    :   MPEGSUB.H

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
    0   |20/02/1997| Initial revision                                     ST
    1   |31/03/1997| First Aminet release                                 ST
    2   |27/04/1997| Added MPEGSUB_init                                   ST
    3   |27/05/1997| Removed IMDCT -> now MPEGIMDCT module                ST
    4   |21/06/1998| Added MPEGSUB_scale                                  ST

    ------------------------------------------------------------------------

    MPEG Audio Common layers Sub routines definitions

------------------------------------------------------------------------------*/

#ifndef MPEGSUB_H
#define MPEGSUB_H

#include "mpegtab.h"

typedef struct {
   MPEGAUD_FRACT_TYPE bb[ MPA_MAX_CHANNELS ][ 2 * MPA_HANNING_SIZE ];
   // #4 Begin
   MPEGTAB_DEW_TYPE scaled_dewindow[ MPA_HANNING_SIZE ];
#ifdef MPEGAUD_INT
   INT32 scaled_shift;
#endif
   INT32 scale_percent;
   // #4 End
   INT16 b_offset[ MPA_MAX_CHANNELS ];
   INT16 freq_div;
   INT16 quality;
   INT16 w_begin;
   INT16 w_width;
   INT16 pcm_count;
} MPEGSUB;


int MPEGSUB_reset( MPEGSUB *mpegsub );
/*-----------------------------------
   Reset the MPEGSUB module
*/

void MPEGSUB_close( MPEGSUB *mpegsub );
/*------------------------------------
   Close the MPEGSUB module
*/

MPEGSUB *MPEGSUB_open( INT16 freq_div, INT16 quality );
/*----------------------------------------------------
   Open the MPEGSUB module
*/


INT16 MPEGSUB_synthesis( MPEGSUB *mpegsub,
                         MPEGAUD_FRACT_TYPE *band_ptr,
                         INT16 channel, INT16 *samples );
/*------------------------------------------------------
   SubBand synthesis filter
   -> Return # of pcm samples calculated
*/

int MPEGSUB_scale( MPEGSUB *mpegsub, INT32 scale_percent ); // #4
/*--------------------------------------------------------
   Set the scale of the output of synthesis filter
   input: scale_percent = scale in % (100 is nominal value)
   return 0 if Ok
*/


#endif /* MPEGSUB_H */
