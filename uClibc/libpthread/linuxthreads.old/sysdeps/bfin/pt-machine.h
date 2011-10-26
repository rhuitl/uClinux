/* Machine-dependent pthreads configuration and inline functions.
   Copyright (C) 1996, 1998, 2000, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Richard Henderson <rth@tamu.edu>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef _PT_MACHINE_H
#define _PT_MACHINE_H   1

#ifndef PT_EI
# define PT_EI extern inline
#endif

extern long int testandset (int *spinlock);

#include <asm/unistd.h>
/* Spinlock implementation; required.  */
/* The semantics of the TESTSET instruction cannot be guaranteed. We cannot
   easily move all locks used by linux kernel to non-cacheable memory.
   EXCPT 0x4 is used to trap into kernel to do the atomic testandset.
   It's ugly. But it's the only thing we can do now.
   The handler of EXCPT 0x4 expects the address of the lock is passed through
   R0. And the result is returned by R0.  */
PT_EI long int
testandset (int *spinlock)
{
  long int res;
  asm volatile ("R0 = %2; P0 = %4; EXCPT 0; %0 = R0;"
                : "=d" (res), "=m" (*spinlock)
                : "d" (spinlock), "m" (*spinlock),
		  "ida" (__NR_bfin_spinlock)
                :"R0", "P0", "cc");
  return res;
}

#endif /* pt-machine.h */
