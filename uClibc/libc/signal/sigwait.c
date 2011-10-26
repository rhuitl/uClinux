/* vi: set sw=4 ts=4: */
/* sigwait
 *
 * Copyright (C) 2003 by Erik Andersen <andersen@uclibc.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.  */

#include <errno.h>
#include <signal.h>
#include <string.h>

libc_hidden_proto(sigwaitinfo)

int __sigwait (const sigset_t *set, int *sig) attribute_hidden;
int __sigwait (const sigset_t *set, int *sig)
{
	int ret = 1;
	if ((ret = sigwaitinfo(set, NULL)) != -1) {
		*sig = ret;
		return 0;
	}
	return 1;
}
libc_hidden_proto(sigwait)
weak_alias(__sigwait,sigwait)
libc_hidden_def(sigwait)
