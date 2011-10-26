/*------------------------------------------------------------------------------

    File    :   MPEGIMDCT.H

    Author  :   Stéphane TAVENARD

    $VER:   MPEGIMDCT.H  0.0  (27/05/1997)

    (C) Copyright 1997-1997 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |27/05/1997| Initial revision                                     ST

    ------------------------------------------------------------------------

    MPEG Audio IMDCT hybrid filter definitions

------------------------------------------------------------------------------*/

#ifndef MPEGIMDCT_H
#define MPEGIMDCT_H

#ifdef MPEGAUD_INT
#define MPEGIMDCT_BLOCK_TYPE MPEGAUD_FRACT_TYPE
#else
#define MPEGIMDCT_BLOCK_TYPE MPEGAUD_FRACT_TYPE
#endif

typedef struct {
   MPEGIMDCT_BLOCK_TYPE prevblk[ 2 ][ 18*32 ];
} MPEGIMDCT;

int MPEGIMDCT_reset( MPEGIMDCT *mpegimdct );
/*-----------------------------------------
   Reset the MPEGIMDCT module
*/

void MPEGIMDCT_close( MPEGIMDCT *mpegimdct );
/*------------------------------------------
   Close the MPEGIMDCT module
*/

MPEGIMDCT *MPEGIMDCT_open( void );
/*-------------------------------
   Open the MPEGIMDCT module
*/

int MPEGIMDCT_hybrid( MPEGIMDCT *mpegimdct, MPEGAUD_FRACT_TYPE *in,
                      MPEGAUD_FRACT_TYPE *out, INT16 block_type, BOOL mixed,
                      INT16 ch, INT16 sb_max );


#endif // MPEGIMDCT_H
