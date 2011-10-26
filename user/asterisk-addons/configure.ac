# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

m4_define([PBX_VERSION],
          m4_bpatsubst(m4_esyscmd([build_tools/make_version .]),
                       [\([0-9.]*\)\(\w\|\W\)*],
                       [\1]))
AC_INIT(asterisk-addons, PBX_VERSION, www.asterisk.org)

# cross-compile macros
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# check existence of the package
AC_CONFIG_SRCDIR([res_config_mysql.c])

AC_COPYRIGHT("Asterisk-addons")
AC_REVISION($Revision: 382 $)

case "${host}" in
     *freebsd*)
     ac_default_prefix=/usr/local
     ;;
     *)
     ac_default_prefix=/usr
     if test ${sysconfdir} = '${prefix}/etc'; then
        sysconfdir=/etc
     fi
     if test ${mandir} = '${prefix}/man'; then
        mandir=/usr/share/man
     fi
     ;;
esac

if test ${localstatedir} = '${prefix}/var'; then
     localstatedir=/var
fi

### ** Platform.
AC_DEFINE_UNQUOTED(PBX_PLATFORM, "${host}",
[Define this to be the canonical name (cpu-vendor-os) of your system.])
AC_DEFINE_UNQUOTED(PBX_CPU, "${host_cpu}",
[Define this to be the name of the CPU of your system.])
AC_DEFINE_UNQUOTED(PBX_VENDOR, "${host_vendor}",
[Define this to be the name of the vendor of your system.])
AC_DEFINE_UNQUOTED(PBX_OS, "${host_os}",
[Define this to be the name of the OS of your system.])

# export some useful defines
PBX_PLATFORM=${host}
PBX_CPU=${host_cpu}
PBX_VENDOR=${host_vendor}
PBX_OS=${host_os}
AC_SUBST(PBX_PLATFORM)
AC_SUBST(PBX_CPU)
AC_SUBST(PBX_VENDOR)
AC_SUBST(PBX_OS)

#  check for uname
AC_PATH_TOOL([UNAME], [uname], No)
if test ! x"${UNAME}" = xNo; then
   PBX_OSREV=$(${UNAME} -r)
fi
AC_SUBST(PBX_OSREV)

# guest OS type
case "${host}" in
  cygwin*|mingw*|windows*|winnt)
    AC_DEFINE(Win32, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="CYGWIN"
# this is ugly - KPF
  OSISWIN32=1
  AC_SUBST(OSISWIN32)
    ;;
  *linux*)
    AC_DEFINE(Linux, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="Linux"
    ;;
  *netbsd*)
    AC_DEFINE(NetBSD, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="NetBSD"
    ;;
  *freebsd*)
    AC_DEFINE(FreeBSD, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="FreeBSD"
    # XXX temporary hack to let FreeBSD use the default paths
    # for local stuff. We need a better solution.
    if test x"${CPPFLAGS}" = x; then
        CPPFLAGS="-I /usr/local/include"
    fi
    if test x"${LDFLAGS}" = x; then
        LDFLAGS="-L /usr/local/lib"
    fi
    ;;
  *openbsd*)
    AC_DEFINE(OpenBSD, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="OpenBSD"
    ;;
  *sun*)
    AC_DEFINE(SunOS, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="SunOS"
    ;;
  *darwin*)
    AC_DEFINE(Darwin, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="Darwin"
    ;;
  *)
    AC_DEFINE(Unix, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="Unix"
   ;;
esac
AC_SUBST(PBX_OSTYPE)

# This needs to be before any macros that use the C compiler
AC_GNU_SOURCE

# cross-compile checks
if test x"${build}" != x"${host}"; 
then
   AC_CHECK_TOOL(CC, gcc, :)
   AC_CHECK_TOOL(CXX, g++, :)
   AC_CHECK_TOOL(RANLIB, ranlib, :)
   AC_CHECK_TOOL(AR, ar, :)

   if test x"${PBX_OSTYPE}" = xWin32;
   then
      AC_CHECK_TOOL(NM, nm, :)
      AC_CHECK_TOOL(WINDRES, windres, :)
      AC_CHECK_TOOL(DLLWRAP, dllwrap, :)
   fi
   crossCompile="Yes"
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AST_CHECK_GNU_MAKE

AC_PATH_PROG([GREP], [grep], :)
AC_PATH_PROG([BASENAME], [basename], :)
AC_PATH_PROG([DIRNAME], [dirname], :)
AC_PATH_PROG([SHELL], [sh], :)
AC_PATH_PROG([LN], [ln], :)

AC_LANG(C)

# from here on down, library checking should be done in alphabetical order
# by the --with option name, to make things easier for the users :-)

AST_EXT_LIB_SETUP([CURSES], [curses], [curses])
AST_EXT_LIB_SETUP([NCURSES], [ncurses], [ncurses])
AST_EXT_LIB_SETUP([MYSQLCLIENT], [mysqlclient], [mysqlclient])
AST_EXT_LIB_SETUP([ASTERISK], [asterisk], [asterisk])

AST_EXT_LIB_CHECK([CURSES], [curses], [initscr], [curses.h])

AST_EXT_LIB_CHECK([NCURSES], [ncurses], [initscr], [curses.h])

MYSQL_CONFIG=No
PBX_MYSQLCLIENT=0
if test "${USE_MYSQLCLIENT}" != "no"; then	
   if test "x${MYSQLCLIENT_DIR}" != "x"; then
      AC_PATH_TOOL([MYSQL_CONFIG], [mysql_config], No, [${MYSQLCLIENT_DIR}/bin])
      if test x"${MYSQL_CONFIG}" = xNo; then
         AC_MSG_NOTICE(***)
         AC_MSG_NOTICE(*** mysql_config was not found in the path you specified:)
         AC_MSG_NOTICE(*** ${MYSQLCLIENT_DIR}/bin)
         AC_MSG_NOTICE(*** Either correct the installation, or run configure)
         AC_MSG_NOTICE(*** including --without-mysqlclient)
         exit 1
      fi
   else
      AC_PATH_TOOL([MYSQL_CONFIG], [mysql_config], No)
   fi
fi
if test x"${MYSQL_CONFIG}" != xNo; then
   MYSQLCLIENT_libs=`mysql_config --libs`
   
   AC_CHECK_LIB([mysqlclient], [mysql_init], [], [], ${MYSQLCLIENT_libs})

   if test "${ac_cv_lib_mysqlclient_mysql_init}" = "yes"; then
      MYSQLCLIENT_LIB="${MYSQLCLIENT_libs}"
      PBX_MYSQLCLIENT=1
   elif test ! -z "${MYSQLCLIENT_MANDATORY}";
   then
      AC_MSG_NOTICE(***)
      AC_MSG_NOTICE(*** The MySQL client installation on this system appears to be broken.)
      AC_MSG_NOTICE(*** Either correct the installation, or run configure)
      AC_MSG_NOTICE(*** including --without-mysqlclient)
      exit 1
   fi
elif test ! -z "${MYSQLCLIENT_MANDATORY}";
then
   AC_MSG_NOTICE(***)
   AC_MSG_NOTICE(*** The MySQL client installation on this system appears to be broken.)
   AC_MSG_NOTICE(*** Either correct the installation, or run configure)
   AC_MSG_NOTICE(*** including --without-mysqlclient)
   exit 1
fi

if test "${USE_ASTERISK}" != "no"; then
   AC_MSG_CHECKING(for asterisk.h)
   saved_cppflags="${CPPFLAGS}"
   if test "x${ASTERISK_DIR}" != "x"; then
      CPPFLAGS="${CPPFLAGS} -I${ASTERISK_DIR}/include"
   fi
   AC_COMPILE_IFELSE(
	[
	AC_LANG_PROGRAM(
	[#include <asterisk.h>],
	[])
	],
	[	AC_MSG_RESULT(yes) 
		ac_cv_asterisk_h="yes" 
	],
	[	AC_MSG_RESULT(no) 
		ac_cv_asterisk_h="no" 
	]
	)
   CPPFLAGS="${saved_cppflags}"
   if test "${ac_cv_asterisk_h}" = "yes"; then
	if test "${ASTERISK_DIR}" != ""; then
	   ASTERISK_INCLUDE="-I${ASTERISK_DIR}/include"
	fi
	PBX_ASTERISK=1
	AC_DEFINE([HAVE_ASTERISK], 1, [Define if your system has the Asterisk headers.])
   elif test ! -z "${ASTERISK_MANDATORY}"; 
   then
      AC_MSG_NOTICE([***])
      AC_MSG_NOTICE([*** The Asterisk installation on this system appears to be broken.])
      AC_MSG_NOTICE([*** Either correct the installation, or run configure])
      AC_MSG_NOTICE([*** including --without-asterisk.])
      exit 1
   fi
fi

AC_CONFIG_FILES([build_tools/menuselect-deps makeopts])
AC_OUTPUT

if test "x${silent}" != "xyes"; then
echo
echo "               .\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$=..      "
echo "            .\$7\$7..          .7\$\$7:.    "
echo "          .\$\$:.                 ,\$7.7   "
echo "        .\$7.     7\$\$\$\$           .\$\$77  "
echo "     ..\$\$.       \$\$\$\$\$            .\$\$\$7 "
echo "    ..7\$   .?.   \$\$\$\$\$   .?.       7\$\$\$."
echo "   \$.\$.   .\$\$\$7. \$\$\$\$7 .7\$\$\$.      .\$\$\$."
echo " .777.   .\$\$\$\$\$\$77\$\$\$77\$\$\$\$\$7.      \$\$\$,"
echo " \$\$\$~      .7\$\$\$\$\$\$\$\$\$\$\$\$\$7.       .\$\$\$."
echo ".\$\$7          .7\$\$\$\$\$\$\$7:          ?\$\$\$."
echo "\$\$\$          ?7\$\$\$\$\$\$\$\$\$\$I        .\$\$\$7 "
echo "\$\$\$       .7\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$      :\$\$\$. "
echo "\$\$\$       \$\$\$\$\$\$7\$\$\$\$\$\$\$\$\$\$\$\$    .\$\$\$.  "
echo "\$\$\$        \$\$\$   7\$\$\$7  .\$\$\$    .\$\$\$.   "
echo "\$\$\$\$             \$\$\$\$7         .\$\$\$.    "
echo "7\$\$\$7            7\$\$\$\$        7\$\$\$      "
echo " \$\$\$\$\$                        \$\$\$       "
echo "  \$\$\$\$7.                       \$\$  (TM)     "
echo "   \$\$\$\$\$\$\$.           .7\$\$\$\$\$\$  \$\$      "
echo "     \$\$\$\$\$\$\$\$\$\$\$\$7\$\$\$\$\$\$\$\$\$.\$\$\$\$\$\$      "
echo "       \$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$.                "
echo
fi

AC_MSG_NOTICE(Package configured for:)
AC_MSG_NOTICE( OS type  : $PBX_OSTYPE)
AC_MSG_NOTICE( Host CPU : $host_cpu)
if test "x${crossCompile}" = xYes; then
   AC_MSG_NOTICE()
   AC_MSG_NOTICE( Cross Compilation = YES)
   AC_MSG_NOTICE( Target            = ${host})
fi
