/*------------------------------------------------------------------------------

    File    :   MPEGIMDA.h

    Author  :   Stéphane TAVENARD

    $VER:   MPEGIMDA.h  0.0  (04/03/1997)

    (C) Copyright 1997-1997 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |04/03/1997| Initial revision                                     ST

    ------------------------------------------------------------------------

    MPEG IMDCT optimzed ! definitions

------------------------------------------------------------------------------*/

#ifndef MPEGIMDA_H
#define MPEGIMDA_H

#include "defs.h"

#ifndef HACK
void MPEGIMDA_hybrid( INT16 *in,
                      INT16 *out,
                      INT16 *prev,
                      INT16 block_type,
                      INT16 mixed,
                      INT16 sb_max );

#else
ASM void MPEGIMDA_hybrid( REG(a0) INT16 *in,
                          REG(a1) INT16 *out,
                          REG(a2) INT16 *prev,
                          REG(d0) INT16 block_type,
                          REG(d1) INT16 mixed,
                          REG(d2) INT16 sb_max );
#endif
#endif /* MPEGIMDA_H */
