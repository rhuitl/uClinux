/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"

#ifdef WANT_WIDE
# define Wmemchr wmemchr
#else
# define Wmemchr memchr
#endif

libc_hidden_proto(Wmemchr)

Wvoid *Wmemchr(const Wvoid *s, Wint c, size_t n)
{
	register const Wuchar *r = (const Wuchar *) s;
#ifdef __BCC__
	/* bcc can optimize the counter if it thinks it is a pointer... */
	register const char *np = (const char *) n;
#else
# define np n
#endif

	while (np) {
		if (*r == ((Wuchar)c)) {
			return (Wvoid *) r;	/* silence the warning */
		}
		++r;
		--np;
	}

	return NULL;
}
#undef np

libc_hidden_def(Wmemchr)
