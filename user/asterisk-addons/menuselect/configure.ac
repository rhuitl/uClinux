# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

m4_define([MENUSELECT_VERSION],
          m4_bpatsubst(m4_esyscmd([./make_version .]),
                       [\([0-9.]*\)\(\w\|\W\)*],
                       [\1]))
AC_INIT(menuselect, MENUSELECT_VERSION, www.asterisk.org)

# check existence of the package
AC_CONFIG_SRCDIR([menuselect.c])

# specify output header file
AC_CONFIG_HEADER(autoconfig.h)

AC_COPYRIGHT("Menuselect")
AC_REVISION($Revision: 40837 $)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

HOST_OS=${host_os}
AC_SUBST(HOST_OS)

AH_TOP(
#ifndef MENUSELECT_AUTOCONFIG_H
#define MENUSELECT_AUTOCONFIG_H

#ifndef _REENTRANT
#define _REENTRANT
#endif
)

AH_BOTTOM(
#endif
)

# Checks for programs.
AC_PROG_CC
AST_CHECK_GNU_MAKE

AC_LANG(C)

AC_CHECK_FUNCS([asprintf getloadavg setenv strcasestr strndup strnlen strsep strtoq unsetenv vasprintf])

AST_EXT_LIB_SETUP([CURSES], [curses], [curses])
AST_EXT_LIB_SETUP([NCURSES], [ncurses], [ncurses])

AST_EXT_LIB_CHECK([CURSES], [curses], [initscr], [curses.h])
AST_EXT_LIB_CHECK([NCURSES], [ncurses], [initscr], [curses.h])

test "$silent"=yes && ac_sub_configure_args="${ac_sub_configure_args} --silent"

AC_CONFIG_FILES([makeopts])
AC_CONFIG_SUBDIRS([mxml])
AC_OUTPUT

AC_MSG_NOTICE(Menuselect build configuration successfully completed)
