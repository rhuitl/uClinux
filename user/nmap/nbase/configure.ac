dnl # -*- mode: fundamental; -*-
dnl # Autoconf configuration file for Nbase
dnl #
dnl # Process this file with autoconf to produce a configure script.
dnl # $Id: configure.ac 3590 2006-06-26 07:58:37Z fyodor $

# Require autoconf 2.13
AC_PREREQ(2.13)

# Include my own macros
sinclude(configlocal.m4)

AC_INIT(nbase.h)

AC_ARG_WITH(localdirs,
  [  --with-localdirs        Explicitly ask compiler to use /usr/local/{include,libs} if they exist ],
  [ case "$with_localdirs" in
      yes)
        user_localdirs=1
        ;;
      no)
        user_localdirs=0
        ;;
    esac
    ],
  [ user_localdirs=0 ] )

if test "$user_localdirs" = 1; then
   if test -d /usr/local/lib; then
     LDFLAGS="$LDFLAGS -L/usr/local/lib"
     fi
   if test -d /usr/local/include; then
     CFLAGS="$CFLAGS -I/usr/local/include"
   fi
fi

dnl use config.h instad of -D macros
AC_CONFIG_HEADER(nbase_config.h)

dnl Checks for programs.
AC_PROG_CC

 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
 fi
AC_PROG_RANLIB
dnl AC_PROG_INSTALL
dnl AC_PATH_PROG(MAKEDEPEND, makedepend)

AC_SUBST(COMPAT_OBJS)
AC_SUBST(COMPAT_SRCS)

dnl Host specific hacks
AC_CANONICAL_HOST

linux=no

case "$host" in
  *-netbsd* | *-knetbsd*-gnu)
    AC_DEFINE(NETBSD)
    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD)
    ;;
  *-sgi-irix5*)
    AC_DEFINE(IRIX)
    if test -z "$GCC"; then
      sgi_cc=yes
    fi
    ;;
  *-sgi-irix6*)
    AC_DEFINE(IRIX)
    if test -z "$GCC"; then
      sgi_cc=yes
    fi
    ;;
  *-hpux*)
    AC_DEFINE(HPUX)
    ;;
  *-solaris2.0*)  
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.[[1-9]][[0-9]]*)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.1*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.2*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.3*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.4*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.5.1)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris*)
    AC_DEFINE(SOLARIS)
    ;;
  *-sunos4*)
    AC_DEFINE(SUNOS)
    AC_DEFINE(SPRINTF_RETURNS_STRING)
    ;;
  *-linux*)
    linux=yes
    AC_DEFINE(LINUX)
    AC_DEFINE(PCAP_TIMEOUT_IGNORED)  # libpcap doesn't even LOOK at
                                     # the timeout you give it under Linux
    ;;
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD)
    ;;
  *-bsdi*)
    AC_DEFINE(BSDI)
    ;;
esac


dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS( string.h getopt.h strings.h memory.h sys/param.h sys/time.h unistd.h bstring.h errno.h sys/types.h sys/socket.h netinet/in.h sys/sockio.h rpc/types.h netdb.h pwd.h arpa/inet.h sys/resource.h sys/stat.h sys/wait.h net/if.h libiberty.h fcntl.h )
AC_CHECK_HEADERS([net/if.h],[],[],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
# endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
# endif
])
AC_CHECK_HEADERS([netinet/if_ether.h],[],[],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
# endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NET_IF_H
# include <net/if.h>
#endif
])

AC_HEADER_TIME

dnl equiv to '#define inline' to 'inline', '__inline__', '__inline' or ''
AC_C_INLINE
if test -n "$sgi_cc"; then
   AC_DEFINE(inline, )
fi

AC_MSG_CHECKING(for __attribute__)
AC_CACHE_VAL(ac_cv___attribute__, [
  AC_TRY_COMPILE(
	[
	#include <stdlib.h>

	static void foo(void) __attribute__ ((noreturn));

	static void
	foo(void)
	{
	  exit(1);
	}
	],
	[
	  foo();
	],
	ac_cv___attribute__=yes,
	ac_cv___attribute__=no
  )
])
if test "$ac_cv___attribute__" = "yes"; then
  AC_DEFINE(HAVE___ATTRIBUTE__, 1, [define if your compiler has __attribute__])
fi
AC_MSG_RESULT($ac_cv___attribute__)

dnl AC_HEADER_TIME

AC_SUBST(CFLAGS)

dnl check endedness
AC_C_BIGENDIAN

dnl If any socket libraries needed
AC_CHECK_FUNC(gethostent, , AC_CHECK_LIB(nsl, gethostent))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt))

dnl determine integer widths so nbase can export u32, u16, etc.
AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(short, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long, 4)

dnl Checks for library functions.
dnl AC_TYPE_SIGNAL
AC_CHECK_FUNCS( bzero snprintf vsnprintf memcpy nanosleep strerror strcasestr strcasecmp strncasecmp signal )

needsnprintf=no
AC_CHECK_FUNCS(vsnprintf snprintf asprintf asnprintf vasprintf vasnprintf,,
        [needsnprintf=yes])
if test $needsnprintf = yes; then
        AC_LIBOBJ([snprintf])
fi

AC_CHECK_FUNCS(usleep gettimeofday sleep, ,
  [ AC_LIBOBJ([nbase_time]) ])

AC_CHECK_FUNC(getopt_long_only, , 
  [ AC_LIBOBJ([getopt])
    AC_LIBOBJ([getopt1]) ])

AC_CHECK_FUNCS(strcasecmp strncasecmp, , 
  [ AC_LIBOBJ([strcasecmp]) ])

# First we test whether they specified openssl desires explicitly
use_openssl="yes"
specialssldir=""

AC_ARG_WITH(openssl,
[  --with-openssl=DIR    Use optional openssl libs and includes from [DIR]/lib/ 
and [DIR]/include/openssl/)],
[  case "$with_openssl" in
  yes)
    ;;
  no)
    use_openssl="no"
    ;;
  *)
    specialssldir="$with_openssl"
    CFLAGS="-I$with_openssl/include $CFLAGS"
    ;;
  esac]
)


# If they didn't specify it, we try to find it
if test "$use_openssl" = "yes" -a -z "$specialssldir" ; then
  AC_CHECK_HEADER(openssl/ssl.h,,
  [ use_openssl="no"
    AC_MSG_WARN([Failed to find openssl/ssl.h so OpenSSL will not be used. If it
 is installed you can try the --with-openssl=DIR argument]) ])

 if test "$use_openssl" = "yes"; then
   AC_CHECK_HEADER(openssl/err.h,,
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find openssl/err.h so OpenSSL will not be used. If it
 is installed you can try the --with-openssl=DIR argument]) ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_HEADER(openssl/rand.h,,
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find openssl/rand.h so OpenSSL will not be used. If i
t is installed you can try the --with-openssl=DIR argument]) ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(crypto, BIO_int_ctrl,
    [],
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find libcrypto so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument]) ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(ssl, SSL_new,
    [],
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find libssl so OpenSSL will not be used. If it is ins
talled you can try the --with-openssl=DIR argument]) ])
 fi
fi

if test "$use_openssl" = "yes"; then
  AC_DEFINE(HAVE_OPENSSL)
fi


dnl We always want some of our files
AC_LIBOBJ([nbase_str])
AC_LIBOBJ([nbase_misc])
AC_LIBOBJ([nbase_memalloc])
AC_LIBOBJ([nbase_rnd])

# Check for IPv6 support -- modified from Apache 2.0.40:

AC_ARG_ENABLE(ipv6,
  [  --disable-ipv6          Disable IPv6 support ],
  [ if test "$enableval" = "no"; then
        user_disabled_ipv6=1
    fi ],
  [ user_disabled_ipv6=0 ] )

AC_SEARCH_LIBS(getaddrinfo, inet6)
AC_SEARCH_LIBS(gai_strerror, inet6)
AC_SEARCH_LIBS(getnameinfo, inet6)
AC_CHECK_FUNCS(gai_strerror)
AC_REPLACE_FUNCS(inet_ntop inet_pton)
APR_CHECK_WORKING_GETADDRINFO
APR_CHECK_WORKING_GETNAMEINFO
APR_CHECK_SOCKADDR_IN6
APR_CHECK_SOCKADDR_STORAGE
CHECK_AF_INET6_DEFINE

AC_MSG_CHECKING(for IPv6 support)
have_ipv6="0"
if test "$user_disabled_ipv6" = 1; then
    AC_MSG_RESULT("no -- disabled by user")
else
    if test "x$have_sockaddr_in6" = "x1"; then
        if test "x$ac_cv_working_getaddrinfo" = "xyes"; then
            if test "x$ac_cv_working_getnameinfo" = "xyes"; then
                have_ipv6="1"
                AC_MSG_RESULT(yes)
            else
                AC_MSG_RESULT("no -- no working getnameinfo")
            fi
        else
            AC_MSG_RESULT("no -- no working getaddrinfo")
        fi
    else
        AC_MSG_RESULT("no -- no sockaddr_in6");
    fi
fi

if test "x$ac_cv_working_getaddrinfo" != "xyes"; then
AC_LIBOBJ([getaddrinfo])
fi

if test "x$ac_cv_working_getnameinfo" != "xyes"; then
AC_LIBOBJ([getnameinfo])
fi

if test "$have_ipv6" = "1"; then
  AC_DEFINE(HAVE_IPV6)
fi

AC_OUTPUT(Makefile)

