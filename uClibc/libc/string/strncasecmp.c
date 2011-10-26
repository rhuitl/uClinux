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
# define strncasecmp wcsncasecmp
# define strncasecmp_l wcsncasecmp_l
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

libc_hidden_proto(strncasecmp_l)

libc_hidden_proto(strncasecmp)
int strncasecmp(register const Wchar *s1, register const Wchar *s2, size_t n)
{
	return strncasecmp_l(s1, s2, n, __UCLIBC_CURLOCALE);
}
libc_hidden_def(strncasecmp)

#else  /* defined(__UCLIBC_HAS_XLOCALE__) && !defined(__UCLIBC_DO_XLOCALE) */

libc_hidden_proto(__XL_NPP(strncasecmp))
int __XL_NPP(strncasecmp)(register const Wchar *s1, register const Wchar *s2,
					  size_t n   __LOCALE_PARAM )
{
#ifdef WANT_WIDE
	while (n && ((*s1 == *s2) || (TOLOWER(*s1) == TOLOWER(*s2)))) {
		if (!*s1++) {
			return 0;
		}
		++s2;
		--n;
	}

	return (n == 0)
		? 0
		: ((((Wuchar)TOLOWER(*s1)) < ((Wuchar)TOLOWER(*s2))) ? -1 : 1);
	/* TODO -- should wide cmp funcs do wchar or Wuchar compares? */
#else
	int r = 0;

	while ( n
			&& ((s1 == s2) ||
				!(r = ((int)( TOLOWER(*((unsigned char *)s1))))
				  - TOLOWER(*((unsigned char *)s2))))
			&& (--n, ++s2, *s1++));
	return r;
#endif
}
libc_hidden_def(__XL_NPP(strncasecmp))

#endif /* defined(__UCLIBC_HAS_XLOCALE__) && !defined(__UCLIBC_DO_XLOCALE) */
