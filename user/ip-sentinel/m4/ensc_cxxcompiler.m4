dnl $Id: ensc_cxxcompiler.m4,v 1.1 2005/03/08 00:01:16 ensc Exp $

dnl Copyright (C) 2002 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
dnl  
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; version 2 of the License.
dnl  
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl  
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

AC_DEFUN([ENSC_CXXCOMPILER],
[
	AC_REQUIRE([AC_PROG_CXX])

	AC_CACHE_CHECK([whether $CXX is a C++ compiler], [ensc_cv_cxx_cxxcompiler],
        [
		AC_LANG_PUSH(C++)
		AC_COMPILE_IFELSE([
		    #include <ostream>
                ],
                [ensc_cv_cxx_cxxcompiler=yes],
                [ensc_cv_cxx_cxxcompiler=no])
		AC_LANG_POP(C++)
        ])

	AM_CONDITIONAL(ENSC_HAVE_CXX_COMPILER,
                       [test x"$ensc_cv_cxx_cxxcompiler" = xyes])

	if test x"$ensc_cv_cxx_cxxcompiler" = xno; then
		AC_MSG_WARN([*** some programs will not be built because a C++ compiler is lacking])
	fi
])

AC_DEFUN([ENSC_C99COMPILER],
[
	AC_REQUIRE([AC_PROG_CC])

	AC_CACHE_CHECK([whether $CC is a C99 compiler], [ensc_cv_c99_c99compiler],
        [
		AC_LANG_PUSH(C)
		AC_COMPILE_IFELSE([
int main(int argc, char *argv[]) {
  struct { int x; }   a = { .x = argc };
  if (0) return 0;
  int b;
}
                ],
                [ensc_cv_c99_c99compiler=yes],
                [ensc_cv_c99_c99compiler=no])
		AC_LANG_POP(C)
        ])

	AM_CONDITIONAL(ENSC_HAVE_C99_COMPILER,
                       [test x"$ensc_cv_c99_c99compiler" = xyes])
])
