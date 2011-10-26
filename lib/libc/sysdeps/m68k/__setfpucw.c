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

#include <fpu_control.h>

void
__setfpucw(unsigned long fpu_control)
{
  unsigned long fpcr;

  /* If user supplied _fpu_control, use it ! */
  if (!fpu_control)
  { 
    /* use linux defaults */
    fpu_control = _FPU_DEFAULT;
  }
  /* Get Floating Point Control Register */
  __asm__ volatile ("fmovel %!,%0" : "=g" (fpcr) : );
  
  /* mask in */
  fpcr &= _FPU_RESERVED;
  fpcr = fpcr | (fpu_control & ~_FPU_RESERVED);

  /* set Control Register */
  __asm__ volatile ("fmovel %0,%!" : : "g" (fpcr));
}
