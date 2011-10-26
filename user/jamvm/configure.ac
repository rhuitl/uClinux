##
## Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008
## Robert Lougher <rob@lougher.org.uk>.
##
## This file is part of JamVM.
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2,
## or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
##

dnl Process this file with autoconf to produce a configure script.

AC_INIT(src/jam.c)
AM_INIT_AUTOMAKE(jamvm, 1.5.1)
AC_CONFIG_HEADERS([src/config.h])
AC_PREFIX_DEFAULT(/usr/local/jamvm)

AC_CANONICAL_HOST

case "$host" in
i[[3456]]86-*-linux*) host_cpu=i386 host_os=linux ;;
i[[3456]]86-*-kfreebsd*) host_cpu=i386 host_os=linux ;;
i[[3456]]86-*-darwin*) host_cpu=i386 host_os=darwin ;;
arm*-*-darwin*) host_cpu=arm host_os=darwin libdl_needed=no ;;
i386-*-openbsd*) host_os=bsd libdl_needed=no ;;
i386-*-freebsd*) host_os=bsd libdl_needed=no ;;
x86_64-*-linux*) host_os=linux ;;
hppa*-*-linux*) host_cpu=parisc host_os=linux ;;
mipsel-*-linux*) host_cpu=mips host_os=linux ;;
amd64-*-openbsd*) host_os=bsd libdl_needed=no ;;
amd64-*-freebsd*) host_os=bsd libdl_needed=no ;;
arm*-*-linux*) host_cpu=arm host_os=linux ;;
arm*-*-openbsd*) host_cpu=arm host_os=bsd libdl_needed=no ;;
arm*-*-freebsd*) host_cpu=arm host_os=bsd libdl_needed=no ;;
powerpc*-*-linux*) host_cpu=powerpc host_os=linux ;;
powerpc*-*-openbsd*) host_cpu=powerpc host_os=bsd libdl_needed=no ;;
powerpc*-*-freebsd*) host_cpu=powerpc host_os=bsd libdl_needed=no ;;
powerpc-*-darwin*) host_os=darwin ;;
*) AC_MSG_ERROR($host not supported) ;;
esac

arch=$host_cpu
os=$host_os
AC_SUBST(arch)
AC_SUBST(os)

AC_ARG_ENABLE(tracegc,
    [AS_HELP_STRING(--enable-tracegc,add gc tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACEGC],1,[defined if gc tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(tracealloc,
    [AS_HELP_STRING(--enable-tracealloc,add object allocation tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACEALLOC],1,[defined if object allocation tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(tracefnlz,
    [AS_HELP_STRING(--enable-tracefnlz,add object finalisation tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACEFNLZ],1,[defined if object finalisation tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(tracedll,
    [AS_HELP_STRING(--enable-tracedll,add library loading/lookup tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACEDLL],1,[defined if library loading/unloading tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(tracelock,
    [AS_HELP_STRING(--enable-tracelock,add object locking tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACELOCK],1,[defined if object locking tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(tracethread,
    [AS_HELP_STRING(--enable-tracethread,add thread creation tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACETHREAD],1,[defined if thread creation tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(tracecompact,
    [AS_HELP_STRING(--enable-tracecompact,add GC compaction phase tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACECOMPACT],1,[defined if GC compaction phase tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(tracedirect,
    [AS_HELP_STRING(--enable-tracedirect,add interpreter direct-mode tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACEDIRECT],1,[defined if interpreter direct-mode tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(traceinlining,
    [AS_HELP_STRING(--enable-traceinlining,add interpreter inlining tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACEINLINING],1,[defined if interpreter inlining tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(trace,
    [AS_HELP_STRING(--enable-trace,add all tracing (for debugging))],
    [if test "$enableval" != no; then
        AC_DEFINE([TRACEGC],1,[defined if gc tracing enabled for debugging])
        AC_DEFINE([TRACEALLOC],1,[defined if object allocation tracing enabled for debugging])
        AC_DEFINE([TRACEFNLZ],1,[defined if object finalisation tracing enabled for debugging])
        AC_DEFINE([TRACEDLL],1,[defined if library loading/unloading tracing enabled for debugging])
        AC_DEFINE([TRACELOCK],1,[defined if object locking tracing enabled for debugging])
        AC_DEFINE([TRACETHREAD],1,[defined if thread creation tracing enabled for debugging])
        AC_DEFINE([TRACECOMPACT],1,[defined if GC compaction phase tracing enabled for debugging])
        AC_DEFINE([TRACEDIRECT],1,[defined if interpreter direct-mode tracing enabled for debugging])
        AC_DEFINE([TRACEINLINING],1,[defined if interpreter inlining tracing enabled for debugging])
    fi],)

AC_ARG_ENABLE(int-threading,
    [AS_HELP_STRING(--enable-int-threading,enable threaded version of the interpreter (default enabled))],,)

AC_ARG_ENABLE(int-direct,
    [AS_HELP_STRING(--enable-int-direct,enable direct threaded version of the interpreter (default enabled))],,)

AC_ARG_ENABLE(int-caching,
    [AS_HELP_STRING(--enable-int-caching,enable stack-caching version of the interpreter
                   (disabled by default on x86-64, enabled otherwise))],,
    [if test "$host_cpu" = x86_64; then
         enable_int_caching=no
     fi])

AC_ARG_ENABLE(int-prefetch,
    [AS_HELP_STRING(--enable-int-prefetch,enable prefetching version of the interpreter
                   (by default enabled on powerpc, disabled otherwise))],,
    [if test "$host_cpu" != powerpc; then
         enable_int_prefetch=no
     fi])

AC_ARG_ENABLE(runtime-reloc-checks,
    [AS_HELP_STRING(--enable-runtime-reloc-checks,compute relocatability at runtime (inlining interpreter))],,
        enable_runtime_reloc_checks=no)

AC_ARG_ENABLE(int-inlining,
    [AS_HELP_STRING(--enable-int-inlining,enable inline threaded version of the interpreter
                   (by default enabled on x86_64, i386 and powerpc, disabled otherwise))],,
    [if test "$host_cpu" = x86_64 -o "$host_cpu" = i386 -o "$host_cpu" = powerpc && \
        test "$cross_compiling" = no -o "$enable_runtime_reloc_checks" != no; then
         enable_int_inlining=yes
       else
         enable_int_inlining=no
     fi])

if test "$enable_int_threading" != no; then
    AC_DEFINE([THREADED],1,[interpreter threaded])

    if test "$enable_int_caching" != no; then
        AC_DEFINE([USE_CACHE],1,[interpreter uses caching])
    fi

    if test "$enable_int_direct" != no; then
        AC_DEFINE([DIRECT],1,[interpreter direct])

        if test "$enable_int_prefetch" != no; then
            AC_DEFINE([PREFETCH],1,[interpreter uses prefetching])
        fi

        if test "$enable_int_inlining" != no; then
            AC_DEFINE([INLINING],1,[interpreter inlining])
            interp_cflags=-fno-reorder-blocks 

            if test "$enable_runtime_reloc_checks" != no; then
                AC_DEFINE([RUNTIME_RELOC_CHECKS],1,[compute relocatability at runtime])
            else
                compile_time_reloc_checks=yes
            fi
        fi
    fi
fi

AC_SUBST(interp_cflags)
AM_CONDITIONAL(COMPILE_TIME_RELOC_CHECKS, test "$compile_time_reloc_checks" = yes)

AC_ARG_ENABLE(ffi,
    [AS_HELP_STRING(--enable-ffi,use libffi to call native methods)],,
    [if test "$host_cpu" != parisc; then
        enable_ffi=no
     fi])

AC_ARG_WITH(classpath-install-dir,
    [AS_HELP_STRING(--with-classpath-install-dir=<dir>,installation directory of GNU classpath
                   (default /usr/local/classpath))],,
    [with_classpath_install_dir=/usr/local/classpath])

AC_DEFINE_UNQUOTED(CLASSPATH_INSTALL_DIR, "$with_classpath_install_dir",
    [GNU Classpath installation directory (prefix)])

AC_SUBST(with_classpath_install_dir)

if test "$prefix" = "NONE"; then
    install_dir=$ac_default_prefix
else
    install_dir=$prefix
fi
AC_DEFINE_UNQUOTED(INSTALL_DIR, "$install_dir", [Installation directory (prefix)])

AC_ARG_ENABLE(zip,
    [AS_HELP_STRING(--disable-zip,turn-off zip support in the bootstrap loader)],,)

dnl Initialise libtool
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

dnl Checks for programs.
AC_PROG_CC
AM_PROG_AS

AC_CHECK_PROGS(JAVAC, ecj jikes "gcj -C" javac)

dnl Checks for libraries.

AC_CHECK_LIB(pthread,pthread_self,,AC_MSG_ERROR(libpthread is missing))
AC_CHECK_LIB(m,fmod,,AC_MSG_ERROR(libm is missing))

if test "$libdl_needed" != no; then
    AC_CHECK_LIB(dl,dlopen,,AC_MSG_ERROR(libdl is missing))
fi

if test "$enable_zip" != no; then
    AC_CHECK_LIB(z,inflate,,AC_MSG_ERROR(zlib is missing))
fi

if test "$enable_ffi" != no; then
    AC_CHECK_LIB(ffi,ffi_call,,AC_MSG_ERROR(libffi is missing))
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/time.h unistd.h endian.h sys/param.h locale.h)

if test "$enable_zip" != no; then
    AC_CHECK_HEADER(zlib.h,,AC_MSG_ERROR(zlib.h is missing))
fi

if test "$enable_ffi" != no; then
    AC_CHECK_HEADER(ffi.h,,AC_MSG_ERROR(ffi.h is missing))
fi

if test "$enable_zip" != no; then
    AC_DEFINE([USE_ZIP],1,[use zip])
    use_zip_yes=
    use_zip_no='#'
else
    use_zip_yes='#'
    use_zip_no=
fi

AC_SUBST(use_zip_yes)
AC_SUBST(use_zip_no)

if test "$enable_ffi" != no; then
    AC_DEFINE([USE_FFI],1,[use FFI])
fi

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_MMAP
AC_CHECK_FUNCS(gettimeofday strtol setlocale)
AM_LC_MESSAGES

AM_MAINTAINER_MODE

AC_CONFIG_LINKS(src/arch.h:src/arch/$arch.h)

AC_CONFIG_FILES(
    Makefile \
    src/Makefile \
    src/interp/Makefile \
    src/interp/engine/Makefile \
    src/arch/Makefile \
    src/os/Makefile \
    src/os/linux/Makefile \
    src/os/darwin/Makefile \
    src/os/bsd/Makefile \
    src/os/linux/powerpc/Makefile \
    src/os/linux/arm/Makefile \
    src/os/linux/i386/Makefile \
    src/os/linux/x86_64/Makefile \
    src/os/linux/parisc/Makefile \
    src/os/linux/mips/Makefile \
    src/os/darwin/i386/Makefile \
    src/os/darwin/arm/Makefile \
    src/os/darwin/powerpc/Makefile \
    src/os/bsd/powerpc/Makefile \
    src/os/bsd/arm/Makefile \
    src/os/bsd/i386/Makefile \
    src/os/bsd/x86_64/Makefile \
    lib/Makefile \
    lib/java/Makefile \
    lib/java/lang/Makefile \
    lib/jamvm/Makefile \
    lib/jamvm/java/Makefile \
    lib/jamvm/java/lang/Makefile \
    lib/java/lang/reflect/Makefile \
    lib/java/security/Makefile \
    lib/gnu/Makefile \
    lib/sun/reflect/annotation/Makefile \
    lib/sun/reflect/Makefile \
    lib/sun/Makefile \
    lib/gnu/classpath/Makefile)

AC_OUTPUT

