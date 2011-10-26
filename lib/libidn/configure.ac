dnl Process this file with autoconf to produce a configure script.

dnl Copyright (C) 2002, 2003, 2004 Simon Josefsson.
dnl
dnl This file is part of GNU Libidn.
dnl
dnl GNU Libidn is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU Lesser General Public License as
dnl published by the Free Software Foundation; either version 2.1 of
dnl the License, or (at your option) any later version.
dnl
dnl GNU Libidn is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with GNU Libidn; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

AC_INIT([libidn], [0.5.2], [bug-libidn@gnu.org])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
LT_CURRENT=15
LT_REVISION=2
LT_AGE=4
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

AC_PREREQ(2.59)
AM_INIT_AUTOMAKE([1.8 gnits])
AB_INIT
AC_CONFIG_HEADERS(config.h)

# Checks for programs.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.14.1)
AC_PROG_LIBTOOL
AC_PROG_CC
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_ICONV
AM_PATH_LISPDIR

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h errno.h)

# Checks for typedefs, structures, and compiler characteristics.
AX_CREATE_STDINT_H(lib/idn-int.h, sys/types.h)

# Need getopt.
GETOPT_H=
AC_CHECK_HEADERS([getopt.h], [], [GETOPT_H=getopt.h])
AC_CHECK_FUNCS([getopt_long_only], [],
  [GETOPT_H=getopt.h
   AC_LIBOBJ([getopt])
   AC_LIBOBJ([getopt1])
   AC_DEFINE([optarg], [rpl_optarg],
     [Define to rpl_optarg if the replacement variable should be used.])
   AC_DEFINE([optind], [rpl_optind],
     [Define to rpl_optind if the replacement variable should be used.])
   AC_DEFINE([optopt], [rpl_optopt],
     [Define to rpl_optopt if the replacement variable should be used.])
   AC_DEFINE([getopt], [rpl_getopt],
     [Define to rpl_getopt if the replacement function should be used.])
   AC_DEFINE([getopt_long], [rpl_getopt_long],
     [Define to rpl_getopt_long if the replacement function should be used.])
   AC_DEFINE([getopt_long_only], [rpl_getopt_long_only],
     [Define to rpl_getopt_long_only if the replacement function should be used.])])
AC_SUBST([GETOPT_H])

# Check if locale stuff works
AC_CACHE_CHECK([if setlocale() and nl_langinfo() works],
	ac_cv_locale_works, [
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <locale.h>
#include <langinfo.h>
int main ()
{
  char* cs;
  setlocale(LC_CTYPE, "");
  cs = nl_langinfo(CODESET);
  return !cs;
}
]])],[ac_cv_locale_works=yes],[ac_cv_locale_works=no],[ac_cv_locale_works=no])
	])
if test "$ac_cv_locale_works" = "yes"; then
  AC_DEFINE(LOCALE_WORKS, 1, [Define if setlocale() and nl_langinfo() works.])
fi

# Make it possible to disable TLD code.
AC_ARG_ENABLE(tld, AC_HELP_STRING([--disable-tld], [disable TLD code]),
		enable_tld=$enableval, enable_tld=yes)
AM_CONDITIONAL(TLD, test "$enable_tld" != "no")
if test "$enable_tld" != "no"; then
	AC_DEFINE(WITH_TLD, 1, [Define to 1 if you want TLD code.])
fi
AC_MSG_CHECKING([if TLD API for specific TLD rules should be built])
AC_MSG_RESULT($enable_tld)

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

# Check for java
AC_ARG_ENABLE(java, AC_HELP_STRING([--enable-java], [enable Java API]),,
		enable_java=no)
if test "$enable_java" != "no"; then
	AC_PROG_JAVAC
	AC_PROG_JAR
	AC_PROG_JAVADOC
fi
AM_CONDITIONAL(JAVA, test "$enable_java" != "no")
AC_MSG_CHECKING([if implementation in Java should be built])
AC_MSG_RESULT($enable_java)

AC_CONFIG_FILES([Makefile libidn.pc doc/reference/Makefile doc/java/Makefile \
		lib/stringprep.h contrib/doxygen/Doxyfile \
		doc/Makefile doc/specifications/Makefile doc/tld/Makefile \
		lib/Makefile src/Makefile tests/Makefile examples/Makefile \
		java/Makefile java/gnu/Makefile java/gnu/inet/Makefile \
		java/gnu/inet/encoding/Makefile java/misc/Makefile \
		po/Makefile.in])
AC_OUTPUT
