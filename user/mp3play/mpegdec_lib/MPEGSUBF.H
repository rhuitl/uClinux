/*------------------------------------------------------------------------------

    File    :   MPEGSUBF.h

    Author  :   Stéphane TAVENARD

    (C) Copyright 1997-1998 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |02/06/1997| Initial revision                                     ST
    1   |01/11/1997| Suppressed static vars                               ST
    2   |21/06/1998| Use external dewindow now                            ST

    ------------------------------------------------------------------------

    MPEG SUBroutines optimized (FPU) !

------------------------------------------------------------------------------*/

#ifndef MPEGSUBF_H
#define MPEGSUBF_H

#ifndef ASM

#ifdef _DCC
#define REG(x) __ ## x
#define ASM
#define SAVEDS __geta4
#else
#define REG(x) register __ ## x
#ifdef __MAXON__
#define ASM
#define SAVEDS
#else
#define ASM    __asm
#define SAVEDS __saveds
#endif
#endif

#endif

/* #1: suppressed
ASM void MPEGSUBF_config( REG(d0) INT16 freq_div,
                          REG(d1) INT16 quality,
                          REG(d2) INT16 output_8bits );
*/

ASM void MPEGSUBF_filter_band( REG(a0) REAL *band_ptr,
                               REG(a1) REAL *out_filter0,
                               REG(a2) REAL *out_filter1,
                               REG(d0) INT16 freq_div /* #1 */ );

ASM void MPEGSUBF_window_band( REG(a0) REAL  *out_filter,
                               REG(a1) INT16 *out_sample,
                               REG(a2) float *dewindow, /* #2 */
                               REG(d0) INT16 buffer_offset,
                               REG(d1) INT16 w_begin,  /* #1 */
                               REG(d2) INT16 w_width , /* #1 */
                               REG(d3) INT32 freq_div  /* #1 */ );

ASM void MPEGSUBF_antialias( REG(a0) REAL *xr, REG(d0) INT16 sblimit );

#endif /* MPEGSUBB_H */
