/* vi: set sw=4 ts=4: */
/*
 * __syscall_ipc() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>

#ifdef __NR_ipc
#define __NR___syscall_ipc __NR_ipc
#include "../../../misc/sysvipc/ipc.h"
_syscall5(int, __syscall_ipc, unsigned int, call, int, first, int, second, int,
		  third, void *, ptr);
#endif
