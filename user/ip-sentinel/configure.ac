## $Id: configure.ac,v 1.35 2005/03/29 16:44:52 ensc Exp $

# Copyright (C) 2002,2003,2004,2005 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
#  
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

AC_INIT(ip-sentinel, 0.12, enrico.scholz@informatik.tu-chemnitz.de, [ip-sentinel])
AC_CONFIG_SRCDIR([src/antidos.c])
AM_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE([gnits dist-bzip2 subdir-objects])
AM_MAINTAINER_MODE

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

if test "$host_os" != "linux-gnu"; then
	AC_MSG_ERROR(["Sorry, build is only supported for GNU/Linux"])
fi

if test "$build_os" != "linux-gnu"; then
	AC_MSG_WARN([
****************************

Builds in non-GNU/Linux environments are not well tested and will fail
probably. To have a minimal chance to succeed, make sure that a recent
GNU 'make' will be used.

****************************])
fi


username=nobody
configfile=ips.cfg

AC_SUBST(GPG_KEY, "0xFFD316AC53ACA43A!")

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_LN_S
AC_PROG_RANLIB

ENSC_C99COMPILER
ENSC_CHANGELOG()

ENSC_STANDARD_TOOLS
ENSC_RELEASE(IS_RELEASE)
ENSC_DEVELOPING(IS_DEVELOPING)

ENSC_ENABLE_DIETLIBC([USE_DIETLIBC], 0.24)
ENSC_DIET_FIX
AC_DEFINE(_GNU_SOURCE, 1, [Uses GNU features])

ENSC_CHECK_CC_FLAG([-Wall -W -Wno-unused-function])
ENSC_CHECK_CC_FLAG([-std=c99 ${RELEASE_CFLAGS} ${DEVELOPING_CFLAGS} ${DEVELOPING_STRICT_CFLAGS} -Wno-unreachable-code])

ENSC_INITRDDIR(initrddir)


AC_MSG_CHECKING([for configfile])
AC_ARG_WITH(configfile,
            AC_HELP_STRING([--with-configfile=DIR],
                           [Path of configfile]),
            [ case x"$withval" in
		x|xyes|xno)	AC_MSG_ERROR("Invalid value for --with-configfile");;
		*)              configfile=${withval};;
	      esac ], [ : ])
AC_MSG_RESULT($configfile)
AC_SUBST(CONFIGFILE, $configfile)

AC_MSG_CHECKING([for username])
AC_ARG_WITH(username,
            AC_HELP_STRING([--with-username=NAME],
                           [Name of user running the sentinel]),
            [ case x"$withval" in
		x|xyes|xno)	AC_MSG_ERROR("Invalid value for --with-username");;
		*)              username=${withval};;
	      esac ], [ : ])
AC_MSG_RESULT($username)
AC_SUBST(USERNAME, $username)

AC_DEFINE_UNQUOTED([SENTINEL_USER],    ["$username"],    [Sentineluser])
AC_DEFINE_UNQUOTED([PATH_CONFIGFILE],  ["$configfile"],  [Configfilename])



ENSC_MODERN_COMPILER_CHECK

AM_CONDITIONAL(ENSC_USE_GLIBC,    test x"$ensc_use_dietlibc" != xyes)
AM_CONDITIONAL(ENSC_USE_DIETLIBC, test x"$ensc_use_dietlibc"  = xyes)

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
ENSC_DIET_CHECK_IN_ADDR_T

# Checks for library functions.
ENSC_DIET_CHECK_ETHER
ENSC_DIET_ENV([AC_CHECK_DECLS([strdupa],[], [], [
#define _GNU_SOURCE
#include <string.h>
		])
])

AH_BOTTOM([#include "compat.h"])
AC_CONFIG_FILES([Makefile
                 src/Makefile ip-sentinel.spec])
AC_OUTPUT
