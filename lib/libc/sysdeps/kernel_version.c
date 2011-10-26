/* vi: set sw=4 ts=4: */
/* find_kernel_revision for uClibc
 *
 * Copyright (C) 2002 by SnapGear, inc. and Paul Dale <pauli@snapgear.com>
 * Copyright (C) 2000 by Lineo, inc. and Erik Andersen
 * Copyright (C) 2000,2001 by Erik Andersen <andersen@uclibc.org>
 * Written by Erik Andersen <andersen@uclibc.org>
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

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

/* Returns kernel version encoded as major*65536 + minor*256 + patch,
 * so, for example,  to check if the kernel is greater than 2.2.11:
 *     if (get_kernel_revision() <= 2*65536+2*256+11) { <stuff> }
 */
int
__get_linux_kernel_version (void)
{
	struct utsname name;
	int major = 0, minor = 0, patch = 0;

	if (uname(&name) == -1) {
		return (0);
	}
	sscanf(name.version, "%d.%d.%d", &major, &minor, &patch);
	return major * 65536 + minor * 256 + patch;
}
