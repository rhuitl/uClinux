/* Extended regular expression matching and search library.
   Copyright (C) 2002, 2003, 2005 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Isamu Hasegawa <isamu@yamato.ibm.com>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* uClibc addons */
#include <features.h>

#ifdef __UCLIBC__
#undef _LIBC
#define _REGEX_RE_COMP
#ifdef __USE_GNU
# define HAVE_MEMPCPY
#endif
#define HAVE_LANGINFO
#define HAVE_LANGINFO_CODESET
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#ifdef __UCLIBC_HAS_WCHAR__
#define RE_ENABLE_I18N
#include <wchar.h>
#include <wctype.h>

#define __iswctype iswctype
#define __wcrtomb wcrtomb
#define __btowc btowc
#define __wctype wctype
libc_hidden_proto(wcscoll)
libc_hidden_proto(wcrtomb)
libc_hidden_proto(mbrtowc)
libc_hidden_proto(iswctype)
libc_hidden_proto(iswlower)
libc_hidden_proto(iswalnum)
libc_hidden_proto(towlower)
libc_hidden_proto(towupper)
libc_hidden_proto(mbsinit)
libc_hidden_proto(btowc)
libc_hidden_proto(wctype)

#endif

#include <ctype.h>
#ifdef __UCLIBC_HAS_CTYPE_TABLES__
#define __toupper toupper
#define __tolower tolower
#endif
#define __mempcpy mempcpy
#ifdef __UCLIBC_HAS_XLOCALE__
libc_hidden_proto(__ctype_b_loc)
libc_hidden_proto(__ctype_toupper_loc)
#elif __UCLIBC_HAS_CTYPE_TABLES__
libc_hidden_proto(__ctype_b)
libc_hidden_proto(__ctype_toupper)
#else
libc_hidden_proto(isascii)
#endif
libc_hidden_proto(toupper)
libc_hidden_proto(tolower)
libc_hidden_proto(memcmp)
libc_hidden_proto(memcpy)
libc_hidden_proto(memmove)
libc_hidden_proto(memset)
libc_hidden_proto(strchr)
libc_hidden_proto(strcmp)
libc_hidden_proto(strlen)
libc_hidden_proto(strncpy)
libc_hidden_proto(getenv)
libc_hidden_proto(strcasecmp)
libc_hidden_proto(abort)
#ifdef __USE_GNU
libc_hidden_proto(mempcpy)
#endif

#endif

/* Make sure noone compiles this code with a C++ compiler.  */
#ifdef __cplusplus
# error "This is C code, use a C compiler"
#endif

#if defined _LIBC || defined __UCLIBC__
/* We have to keep the namespace clean.  */
# define regfree(preg) __regfree (preg)
# define regexec(pr, st, nm, pm, ef) __regexec (pr, st, nm, pm, ef)
# define regcomp(preg, pattern, cflags) __regcomp (preg, pattern, cflags)
# define regerror(errcode, preg, errbuf, errbuf_size) \
	__regerror(errcode, preg, errbuf, errbuf_size)
# define re_set_registers(bu, re, nu, st, en) \
	__re_set_registers (bu, re, nu, st, en)
# define re_match_2(bufp, string1, size1, string2, size2, pos, regs, stop) \
	__re_match_2 (bufp, string1, size1, string2, size2, pos, regs, stop)
# define re_match(bufp, string, size, pos, regs) \
	__re_match (bufp, string, size, pos, regs)
# define re_search(bufp, string, size, startpos, range, regs) \
	__re_search (bufp, string, size, startpos, range, regs)
# define re_compile_pattern(pattern, length, bufp) \
	__re_compile_pattern (pattern, length, bufp)
# define re_set_syntax(syntax) __re_set_syntax (syntax)
# define re_search_2(bufp, st1, s1, st2, s2, startpos, range, regs, stop) \
	__re_search_2 (bufp, st1, s1, st2, s2, startpos, range, regs, stop)
# define re_compile_fastmap(bufp) __re_compile_fastmap (bufp)

#ifndef __UCLIBC__
# include "../locale/localeinfo.h"
#endif
#endif

/* On some systems, limits.h sets RE_DUP_MAX to a lower value than
   GNU regex allows.  Include it before <regex.h>, which correctly
   #undefs RE_DUP_MAX and sets it to the right value.  */
#include <limits.h>

#ifdef __UCLIBC__
#include "_regex.h"
#else
#include <regex.h>
#endif
#include "regex_internal.h"

#include "regex_internal.c"
#include "regcomp.c"
#include "regexec.c"

/* Binary backward compatibility.  */
#if _LIBC
# include <shlib-compat.h>
# if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_3)
link_warning (re_max_failures, "the 're_max_failures' variable is obsolete and will go away.")
int re_max_failures = 2000;
# endif
#endif
