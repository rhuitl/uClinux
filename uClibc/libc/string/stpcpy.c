/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"

#ifdef WANT_WIDE
# define Wstpcpy wcpcpy
#else
libc_hidden_proto(stpcpy)
# define Wstpcpy stpcpy
#endif

Wchar *Wstpcpy(register Wchar * __restrict s1, const Wchar * __restrict s2)
{
#ifdef __BCC__
	do {
		*s1 = *s2++;
	} while (*s1++ != 0);
#else
	while ( (*s1++ = *s2++) != 0 );
#endif

	return s1 - 1;
}

#ifndef WANT_WIDE
libc_hidden_def(stpcpy)
#endif
