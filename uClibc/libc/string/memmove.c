/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"

#ifdef WANT_WIDE
# define Wmemmove wmemmove
#else
libc_hidden_proto(memmove)
# define Wmemmove memmove
#endif

Wvoid *Wmemmove(Wvoid *s1, const Wvoid *s2, size_t n)
{
#ifdef __BCC__
	register Wchar *s = (Wchar *) s1;
	register const Wchar *p = (const Wchar *) s2;

	if (p >= s) {
		while (n--) {
			*s++ = *p++;
		}
	} else {
		s += n;
		p += n;
		while (n--) {
			*--s = *--p;
		}
	}

	return s1;
#else
	register Wchar *s = (Wchar *) s1;
	register const Wchar *p = (const Wchar *) s2;

	if (p >= s) {
		while (n) {
			*s++ = *p++;
			--n;
		}
	} else {
		while (n) {
			--n;
			s[n] = p[n];
		}
	}

	return s1;
#endif
}

#ifndef WANT_WIDE
libc_hidden_def(Wmemmove)
#endif
