/* Copyright (C) 1995 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#ifndef _M68K_IEEEFP_H
#define _M68k_IEEEFP_H

union m68881_float
{
  float f;

  /* This is the m68881 single-precision format.  */
  struct
    {
      unsigned int negative:1;
      unsigned int exponent:8;
      unsigned int mantissa:23;
    } m68881;
  /* This is for extracting information about NaNs.  */
  struct
    {
      unsigned int negative:1;
      unsigned int exponent:8;
      unsigned int quiet_nan:1;
      unsigned int mantissa:22;
    } m68881_nan;
};

#define _M68881_FLOAT_BIAS            0x7f   /* added to exp of m68881_float */

#endif	/* _M68k_IEEEFP_H */
