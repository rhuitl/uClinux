/*------------------------------------------------------------------------------

    File    :   MPEGSUBB.h

    Author  :   Stéphane TAVENARD

    (C) Copyright 1997-1998 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |10/04/1997| Initial revision                                     ST
    1   |01/11/1997| Suppressed static vars                               ST
    2   |21/06/1998| Use external dewindow                                ST

    ------------------------------------------------------------------------

    MPEG SUBroutines optimized !

------------------------------------------------------------------------------*/

#ifndef MPEGSUBB_H
#define MPEGSUBB_H

#include "defs.h"

/* #1: suppressed
ASM void MPEGSUBB_config( REG(d0) INT16 freq_div,
                          REG(d1) INT16 quality,
                          REG(d2) INT16 output_8bits );
*/
ASM void MPEGSUBB_filter_band( REG(a0) INT16 *band_ptr,
                               REG(a1) INT16 *out_filter0,
                               REG(a2) INT16 *out_filter1,
                               REG(d0) INT16 freq_div /* #1 */ );

ASM void MPEGSUBB_window_band( REG(a0) INT16 *out_filter,
                               REG(a1) INT16 *out_sample,
                               REG(a2) INT16 *dewindow, /* #2 */
                               REG(d0) INT16 buffer_offset,
                               REG(d1) INT16 w_begin,  /* #1 */
                               REG(d2) INT16 w_width , /* #1 */
                               REG(d3) INT16 freq_div, /* #1 */
                               REG(d4) INT32 dew_shift /* #2 */ );

ASM void MPEGSUBB_antialias( REG(a0) INT16 *xr, REG(d0) INT16 sblimit );

#endif /* MPEGSUBB_H */
