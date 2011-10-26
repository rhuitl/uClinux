/* vi: set sw=4 ts=4: */
/* syscall for blackfin/uClibc
 *
 * Copyright (C) 2004-2006 by Analog Devices Inc.
 * Copyright (C) 2002 by Erik Andersen <andersen@uclibc.org>
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
	int _r0 = 0;

	__asm__ __volatile__ (
		"R5 = %7;"
		"R4 = %6;"
		"R3 = %5;"
		"R2 = %4;"
		"R1 = %3;"
		"R0 = %2;"
		"P0 = %1;"
		"excpt 0;"
		"%0 = R0;"
		: "=r" (_r0)
		: "rm" (sysnum),
		  "rm" (a),
		  "rm" (b),
		  "rm" (c),
		  "rm" (d),
		  "rm" (e),
		  "rm" (f)
		: "memory","CC","R0","R1","R2","R3","R4","R5","P0");

	if (_r0 >= (unsigned long) -4095) {
		(*__errno_location()) = (-_r0);
		_r0 = (unsigned long) -1;
	}

	return (long)_r0;
}
