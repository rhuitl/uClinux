/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"

#ifdef __UCLIBC_SUSV3_LEGACY__

libc_hidden_proto(memset)

void bzero(void *s, size_t n)
{
#if 1
	(void)memset(s, 0, n);
#else
	register unsigned char *p = s;
#ifdef __BCC__
	/* bcc can optimize the counter if it thinks it is a pointer... */
	register const char *np = (const char *) n;
#else
#define np n
#endif

	while (np) {
		*p++ = 0;
		--np;
	}
#endif
}
#undef np
#endif
