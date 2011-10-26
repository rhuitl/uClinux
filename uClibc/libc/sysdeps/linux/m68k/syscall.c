/* syscall for m68k/uClibc
 *
 * Copyright (C) 2005-2006 by Christian Magnusson <mag@mag.cx>
 * Copyright (C) 2005-2006 Erik Andersen <andersen@uclibc.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
                                                                               
#include <features.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>

long syscall(long sysnum, long a, long b, long c, long d, long e, long f)
{
  long __res;
  __asm__ __volatile__ ("movel  %7, %%d6\n\t"\
                        "movel  %6, %%d5\n\t"\
                        "movel  %5, %%d4\n\t"\
                        "movel  %4, %%d3\n\t"\
                        "movel  %3, %%d2\n\t"\
                        "movel  %2, %%d1\n\t"\
                        "movel  %1, %%d0\n\t"\
                        "trap   #0\n\t"\
                        "movel  %%d0, %0"\
                        : "=g" (__res)\
                        : "g" (sysnum),\
			"a" ((long)a),\
			"a" ((long)b),\
			"a" ((long)c),\
			"a" ((long)d),\
			"a" ((long)e),\
			"g" ((long)f)\
                        : "cc", "%d0", "%d1", "%d2", "%d3",\
			"%d4", "%d5", "%d6");
  __syscall_return(long,__res);
}
