/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"
#include <strings.h>
#include <ctype.h>
#include <locale.h>

#ifdef WANT_WIDE
# define strcasecmp wcscasecmp
# define strcasecmp_l wcscasecmp_l
# ifdef __UCLIBC_DO_XLOCALE
libc_hidden_proto(towlower_l)
#  define TOLOWER(C) towlower_l((C), locale_arg)
# else
libc_hidden_proto(towlower)
#  define TOLOWER(C) towlower((C))
# endif
#else
# ifdef __UCLIBC_DO_XLOCALE
libc_hidden_proto(tolower_l)
#  define TOLOWER(C) tolower_l((C), locale_arg)
# else
#if !defined __UCLIBC_HAS_XLOCALE__ && defined __UCLIBC_HAS_CTYPE_TABLES__
libc_hidden_proto(__ctype_tolower)
#endif
libc_hidden_proto(tolower)
#  define TOLOWER(C) tolower((C))
# endif
#endif

#if defined(__UCLIBC_HAS_XLOCALE__) && !defined(__UCLIBC_DO_XLOCALE)

libc_hidden_proto(strcasecmp_l)

libc_hidden_proto(strcasecmp)
int strcasecmp(register const Wchar *s1, register const Wchar *s2)
{
	return strcasecmp_l(s1, s2, __UCLIBC_CURLOCALE);
}
libc_hidden_def(strcasecmp)

#else  /* defined(__UCLIBC_HAS_XLOCALE__) && !defined(__UCLIBC_DO_XLOCALE) */

libc_hidden_proto(__XL_NPP(strcasecmp))
int __XL_NPP(strcasecmp)(register const Wchar *s1, register const Wchar *s2
					  __LOCALE_PARAM )
{
#ifdef WANT_WIDE
	while ((*s1 == *s2) || (TOLOWER(*s1) == TOLOWER(*s2))) {
		if (!*s1++) {
			return 0;
		}
		++s2;
	}

	return (((Wuchar)TOLOWER(*s1)) < ((Wuchar)TOLOWER(*s2))) ? -1 : 1;
	/* TODO -- should wide cmp funcs do wchar or Wuchar compares? */
#else
	int r = 0;

	while ( ((s1 == s2) ||
			 !(r = ((int)( TOLOWER(*((Wuchar *)s1))))
			   - TOLOWER(*((Wuchar *)s2))))
			&& (++s2, *s1++));

	return r;
#endif
}
libc_hidden_def(__XL_NPP(strcasecmp))

#endif /* defined(__UCLIBC_HAS_XLOCALE__) && !defined(__UCLIBC_DO_XLOCALE) */
