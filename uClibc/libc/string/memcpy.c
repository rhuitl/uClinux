/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"

#ifdef WANT_WIDE
# define Wmemcpy wmemcpy
#else
# define Wmemcpy memcpy
#endif

libc_hidden_proto(Wmemcpy)

Wvoid *Wmemcpy(Wvoid * __restrict s1, const Wvoid * __restrict s2, size_t n)
{
	register Wchar *r1 = s1;
	register const Wchar *r2 = s2;

#ifdef __BCC__
	while (n--) {
		*r1++ = *r2++;
	}
#else
	while (n) {
		*r1++ = *r2++;
		--n;
	}
#endif

	return s1;
}
libc_hidden_def(Wmemcpy)
