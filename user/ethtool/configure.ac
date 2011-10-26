dnl Process this file with autoconf to produce a configure script.
AC_INIT(ethtool, 5, [Jeff Garzik <jgarzik@pobox.com>])
AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([ethtool.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([ethtool-config.h])

AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL

dnl Checks for libraries.

dnl Checks for header files.
AC_CHECK_HEADERS(sys/ioctl.h)

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.
AC_HEADER_STDC
AC_CHECK_FUNCS(socket strtol)

AC_CONFIG_FILES([Makefile ethtool.spec])
AC_OUTPUT
