/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2007 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __NR_waitid
_syscall4(int, waitid, idtype_t, idtype, id_t, id, siginfo_t*, infop, int, options);
#endif
