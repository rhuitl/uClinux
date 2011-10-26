/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"

#ifdef WANT_WIDE
# define Wmemset wmemset
#else
libc_hidden_proto(memset)
# define Wmemset memset
#endif

Wvoid *Wmemset(Wvoid *s, Wint c, size_t n)
{
	register Wuchar *p = (Wuchar *) s;
#ifdef __BCC__
	/* bcc can optimize the counter if it thinks it is a pointer... */
	register const char *np = (const char *) n;
#else
# define np n
#endif

	while (np) {
		*p++ = (Wuchar) c;
		--np;
	}

	return s;
}
#undef np

#ifndef WANT_WIDE
libc_hidden_def(memset)
#endif
