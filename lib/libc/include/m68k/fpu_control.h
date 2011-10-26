/* Copyright (C) 1993  Olaf Flebbe
This file is part of the Linux C Library.

The Linux C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The Linux C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.  */

#ifndef _M68K_FPU_CONTROL_H
#define _M68K_FPU_CONTROL_H

/*
 * Motorola floating point control register bits.
 *
 * 31-16  -> reserved (read as 0, ignored on write)
 * 15     -> enable trap for BSUN exception
 * 14     -> enable trap for SNAN exception
 * 13     -> enable trap for OPERR exception
 * 12     -> enable trap for OVFL exception
 * 11     -> enable trap for UNFL exception
 * 10     -> enable trap for DZ exception
 *  9     -> enable trap for INEX2 exception
 *  8     -> enable trap for INEX1 exception
 *  7-6   -> Precision Control
 *  5-4   -> Rounding Control
 *  3-0   -> zero (read as 0, write as 0)
 *
 * 
 * Precision Control:
 * 00 - round to extended precision
 * 01 - round to single precision
 * 10 - round to double precision
 * 11 - undefined
 *
 * Rounding Control:
 * 00 - rounding to nearest (RN)
 * 01 - rounding toward zero (RZ)
 * 10 - rounding (down)toward minus infinity (RM)
 * 11 - rounding (up) toward plus infinity (RP)
 *
 * The hardware default is 0x0000. I choose 0x5400.
 */

#include <features.h>

/* masking of interrupts */
#define _FPU_MASK_BSUN  0x8000  
#define _FPU_MASK_SNAN  0x4000
#define _FPU_MASK_OPERR 0x2000
#define _FPU_MASK_OVFL  0x1000
#define _FPU_MASK_UNFL  0x0800
#define _FPU_MASK_DZ    0x0400
#define _FPU_MASK_INEX1 0x0200
#define _FPU_MASK_INEX2 0x0100

/* precision control */
#define _FPU_EXTENDED 0x00   /* RECOMMENDED */
#define _FPU_DOUBLE   0x80
#define _FPU_SINGLE   0x40     /* DO NOT USE */

/* rounding control */
#define _FPU_RC_NEAREST 0x00    /* RECOMMENDED */
#define _FPU_RC_ZERO    0x10
#define _FPU_RC_DOWN    0x20
#define _FPU_RC_UP      0x30

#define _FPU_RESERVED 0xFFFF000F  /* Reserved bits in cw */


/* Now two recommended cw */

/* Linux default:
     - extended precision
     - rounding to nearest
     - exceptions on overflow, zero divide and NaN */
#if 0
#define _FPU_DEFAULT  0x00005400
#else
/* Don't enable execptions any more.  It caused too much grief.  */
#define _FPU_DEFAULT  0x00000000
#endif

/* IEEE:  same as above, but exceptions.  We must make it non-zero so
   that __setfpucw works.  This bit will be ignored.  */
#define _FPU_IEEE     0x00000001

/* private namespace. It should only be used by crt0.o. */
extern unsigned long __fpu_control;

__BEGIN_DECLS

/* called by crt0.o. It can be used to manipulate fpu control register. */
extern void __setfpucw __P ((unsigned long));

__END_DECLS

#endif /* _M68K_FPU_CONTROL_H */
