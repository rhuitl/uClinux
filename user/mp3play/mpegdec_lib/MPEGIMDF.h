/*------------------------------------------------------------------------------

    File    :   MPEGIMDF.h

    Author  :   Stéphane TAVENARD

    $VER:   MPEGIMDF.h  0.0  (04/06/1997)

    (C) Copyright 1997-1997 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |04/06/1997| Initial revision                                     ST

    ------------------------------------------------------------------------

    MPEG IMDCT optimzed ! (FPU Version) definitions

------------------------------------------------------------------------------*/

#ifndef MPEGIMDF_H
#define MPEGIMDF_H

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

ASM void MPEGIMDF_hybrid( REG(a0) float *in,
                          REG(a1) float *out,
                          REG(a2) float *prev,
                          REG(d0) INT16 block_type,
                          REG(d1) INT16 mixed,
                          REG(d2) INT16 sb_max );

ASM void MPEGIMDF_long( REG(a0) float *in,
                        REG(a1) float *out,
                        REG(a2) float *win,
                        REG(a3) float *prev );

ASM void MPEGIMDF_short( REG(a0) float *in,
                        REG(a1) float *out,
                        REG(a2) float *win,
                        REG(a3) float *prev );

#endif /* MPEGIMDF_H */
