/* vi: set sw=4 ts=4: */
/*
 * sigaltstack() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <signal.h>

#ifdef __NR_sigaltstack
_syscall2(int, sigaltstack, const struct sigaltstack *, ss,
		  struct sigaltstack *, oss);
#endif
