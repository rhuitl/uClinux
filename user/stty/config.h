/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define if on AIX 3.
   System headers sometimes define this.
   We just want to avoid a redefinition error message.  */
#ifndef _ALL_SOURCE
/* #undef _ALL_SOURCE */
#endif

/* Define if using alloca.c.  */
/* #undef C_ALLOCA */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define to one of _getb67, GETB67, getb67 for Cray-2 and Cray-YMP systems.
   This function is required for alloca.c support on those systems.  */
/* #undef CRAY_STACKSEG_END */

/* Define for DGUX with <sys/dg_sys_info.h>.  */
/* #undef DGUX */

/* Define to the type of elements in the array set by `getgroups'.
   Usually this is either `int' or `gid_t'.  */
#define GETGROUPS_T gid_t

/* Define if the `getloadavg' function needs to be run setuid or setgid.  */
/* #undef GETLOADAVG_PRIVILEGED */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef gid_t */

/* Define if you have alloca, as a function or macro.  */
#define HAVE_ALLOCA 1

/* Define if you have <alloca.h> and it should be used (not on Ultrix).  */
#define HAVE_ALLOCA_H 1

/* Define if you don't have vprintf but do have _doprnt.  */
/* #undef HAVE_DOPRNT */

/* Define if your system has its own `getloadavg' function.  */
/* #undef HAVE_GETLOADAVG */

/* Define if you have a working `mmap' system call.  */
#define HAVE_MMAP 1

/* Define if you have the strftime function.  */
/* #undef HAVE_STRFTIME */

/* Define if your struct tm has tm_zone.  */
#define HAVE_TM_ZONE 1

/* Define if you don't have tm_zone but do have the external array
   tzname.  */
/* #undef HAVE_TZNAME */

/* Define if you have the vprintf function.  */
#define HAVE_VPRINTF 1

/* Define as __inline if that's what the C compiler calls it.  */
/* #undef inline */

/* Define if on MINIX.  */
/* #undef _MINIX */

/* Define if your struct nlist has an n_un member.  */
/* #undef NLIST_NAME_UNION */

/* Define if you have <nlist.h>.  */
/* #undef NLIST_STRUCT */

/* Define to `long' if <sys/types.h> doesn't define.  */
/* #undef off_t */

/* Define if the system does not provide POSIX.1 features except
   with this defined.  */
/* #undef _POSIX_1_SOURCE */

/* Define if you need to in order for stat and other things to work.  */
/* #undef _POSIX_SOURCE */

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at run-time.
 STACK_DIRECTION > 0 => grows toward higher addresses
 STACK_DIRECTION < 0 => grows toward lower addresses
 STACK_DIRECTION = 0 => direction of growth unknown
 */
/* #undef STACK_DIRECTION */

/* Define if the `S_IS*' macros in <sys/stat.h> do not work properly.  */
/* #undef STAT_MACROS_BROKEN */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define on System V Release 4.  */
#define SVR4 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define if your <sys/time.h> declares struct tm.  */
/* #undef TM_IN_SYS_TIME */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef uid_t */

/* Define for Encore UMAX.  */
/* #undef UMAX */

/* Define for Encore UMAX 4.3 that has <inq_status/cpustats.h>
   instead of <sys/cpustats.h>.  */
/* #undef UMAX4_3 */

/* Define if your processor stores words with the most significant
   byte first (like Motorola and SPARC, unlike Intel and VAX).  */
/* #undef WORDS_BIGENDIAN */

/* Define if using getloadavg.c.  */
#define C_GETLOADAVG 1

/* Define as rpl_getgroups if getgroups doesn't work right.  */
/* #undef getgroups */

/* Define if your system defines TIOCGWINSZ in sys/pty.h.  */
/* #undef GWINSZ_IN_SYS_PTY */

/* Define if your system defines TIOCGWINSZ in sys/ioctl.h.  */
#define GWINSZ_IN_SYS_IOCTL 1

/* Define to 1 if NLS is requested.  */
/* #define ENABLE_NLS 1 */

/* Define as 1 if you have catgets and don't want to use GNU gettext.  */
/* #undef HAVE_CATGETS */

/* Define if your system's definition of `struct termios' has a member
   named c_line.  */
#define HAVE_C_LINE 1

/* Define as 1 if you have gettext and don't want to use GNU gettext.  */
#define HAVE_GETTEXT 1

/* Define if your locale.h file contains LC_MESSAGES.  */
#define HAVE_LC_MESSAGES 1

/* Define if your system has the /proc/uptime special file.  */
#define HAVE_PROC_UPTIME 1

/* Define if your system has SysV shadow passwords and the shadow.h header.  */
#define HAVE_SHADOW_H 1

/* Define to 1 if you have the stpcpy function.  */
#define HAVE_STPCPY 1

/* Define if you have the syslog function.  */
#define HAVE_SYSLOG 1

/* Define if your system's struct utmp has a member named ut_host.  */
#define HAVE_UT_HOST 1

/* Define if you have the <utmpx.h> header file.  */
/* #undef HAVE_UTMPX_H */

/* Define if localtime caches TZ, despite what Posix requires.  */
/* #undef LOCALTIME_CACHE */

/* Define to rpl_memcmp if the replacement function should be used.  */
/* #undef memcmp */

/* Define to rpl_mktime if the replacement function should be used.  */
/* #undef mktime */

/* Define if your system lacks the getpriority and setpriority system calls,
   but has `nice' instead.  */
/* #undef NICE_PRIORITY */

/* Define to the name of the distribution.  */
#define PACKAGE "sh-utils"

/* The concatenation of the strings "GNU ", and PACKAGE.  */
#define GNU_PACKAGE "GNU sh-utils"

/* Define to 1 if ANSI function prototypes are usable.  */
#define PROTOTYPES 1

/* Define to gnu_strftime if the replacement function should be used.  */
/* #undef strftime */

/* Define if you need _XOPEN_SOURCE in order to make termios.h define
   all of the useful symbols.  */
/* #undef TERMIOS_NEEDS_XOPEN_SOURCE */

/* Define to the version of the distribution.  */
#define VERSION "1.16"

/* Define if your system defines `struct winsize' in sys/ptem.h.  */
/* #undef WINSIZE_IN_PTEM */

/* Define if you have the __argz_count function.  */
#define HAVE___ARGZ_COUNT 1

/* Define if you have the __argz_next function.  */
#define HAVE___ARGZ_NEXT 1

/* Define if you have the __argz_stringify function.  */
#define HAVE___ARGZ_STRINGIFY 1

/* Define if you have the basename function.  */
#define HAVE_BASENAME 1

/* Define if you have the bcopy function.  */
#define HAVE_BCOPY 1

/* Define if you have the chroot function.  */
#define HAVE_CHROOT 1

/* Define if you have the crypt function.  */
/* #undef HAVE_CRYPT */

/* Define if you have the dcgettext function.  */
#define HAVE_DCGETTEXT 1

/* Define if you have the endgrent function.  */
#define HAVE_ENDGRENT 1

/* Define if you have the endpwent function.  */
#define HAVE_ENDPWENT 1

/* Define if you have the floor function.  */
#define HAVE_FLOOR 1

/* Define if you have the ftime function.  */
#define HAVE_FTIME 1

/* Define if you have the getcwd function.  */
#define HAVE_GETCWD 1

/* Define if you have the getdelim function.  */
/* #undef HAVE_GETDELIM */

/* Define if you have the getgroups function.  */
#define HAVE_GETGROUPS 1

/* Define if you have the gethostbyaddr function.  */
#define HAVE_GETHOSTBYADDR 1

/* Define if you have the gethostbyname function.  */
#define HAVE_GETHOSTBYNAME 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getloadavg function.  */
/* #undef HAVE_GETLOADAVG */

/* Define if you have the getpagesize function.  */
#define HAVE_GETPAGESIZE 1

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the getusershell function.  */
#define HAVE_GETUSERSHELL 1

/* Define if you have the inet_ntoa function.  */
#define HAVE_INET_NTOA 1

/* Define if you have the initgroups function.  */
#define HAVE_INITGROUPS 1

/* Define if you have the isascii function.  */
#define HAVE_ISASCII 1

/* Define if you have the memcpy function.  */
#define HAVE_MEMCPY 1

/* Define if you have the memset function.  */
#define HAVE_MEMSET 1

/* Define if you have the modf function.  */
#define HAVE_MODF 1

/* Define if you have the munmap function.  */
#define HAVE_MUNMAP 1

/* Define if you have the pow function.  */
/* #undef HAVE_POW */

/* Define if you have the pstat_getdynamic function.  */
/* #undef HAVE_PSTAT_GETDYNAMIC */

/* Define if you have the putenv function.  */
#define HAVE_PUTENV 1

/* Define if you have the rint function.  */
#define HAVE_RINT 1

/* Define if you have the setenv function.  */
#define HAVE_SETENV 1

/* Define if you have the sethostname function.  */
#define HAVE_SETHOSTNAME 1

/* Define if you have the setlocale function.  */
#define HAVE_SETLOCALE 1

/* Define if you have the sqrt function.  */
/* #undef HAVE_SQRT */

/* Define if you have the stime function.  */
#define HAVE_STIME 1

/* Define if you have the stpcpy function.  */
#define HAVE_STPCPY 1

/* Define if you have the strcasecmp function.  */
#define HAVE_STRCASECMP 1

/* Define if you have the strchr function.  */
#define HAVE_STRCHR 1

/* Define if you have the strcspn function.  */
#define HAVE_STRCSPN 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strrchr function.  */
#define HAVE_STRRCHR 1

/* Define if you have the strstr function.  */
#define HAVE_STRSTR 1

/* Define if you have the strtol function.  */
#define HAVE_STRTOL 1

/* Define if you have the strtoul function.  */
#define HAVE_STRTOUL 1

/* Define if you have the sysinfo function.  */
#define HAVE_SYSINFO 1

/* Define if you have the syslog function.  */
#define HAVE_SYSLOG 1

/* Define if you have the tzset function.  */
#define HAVE_TZSET 1

/* Define if you have the uname function.  */
#define HAVE_UNAME 1

/* Define if you have the <argz.h> header file.  */
#define HAVE_ARGZ_H 1

/* Define if you have the <arpa/inet.h> header file.  */
#define HAVE_ARPA_INET_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <float.h> header file.  */
#define HAVE_FLOAT_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <locale.h> header file.  */
/* #define HAVE_LOCALE_H 1 */

/* Define if you have the <mach/mach.h> header file.  */
/* #undef HAVE_MACH_MACH_H */

/* Define if you have the <malloc.h> header file.  */
#define HAVE_MALLOC_H 1

/* Define if you have the <netdb.h> header file.  */
#define HAVE_NETDB_H 1

/* Define if you have the <netinet/in.h> header file.  */
#define HAVE_NETINET_IN_H 1

/* Define if you have the <nl_types.h> header file.  */
#define HAVE_NL_TYPES_H 1

/* Define if you have the <paths.h> header file.  */
#define HAVE_PATHS_H 1

/* Define if you have the <stdlib.h> header file.  */
#define HAVE_STDLIB_H 1

/* Define if you have the <string.h> header file.  */
#define HAVE_STRING_H 1

/* Define if you have the <sys/param.h> header file.  */
#define HAVE_SYS_PARAM_H 1

/* Define if you have the <sys/socket.h> header file.  */
#define HAVE_SYS_SOCKET_H 1

/* Define if you have the <sys/systeminfo.h> header file.  */
/* #undef HAVE_SYS_SYSTEMINFO_H */

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/timeb.h> header file.  */
#define HAVE_SYS_TIMEB_H 1

/* Define if you have the <syslog.h> header file.  */
#define HAVE_SYSLOG_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the <values.h> header file.  */
#define HAVE_VALUES_H 1

/* Define if you have the crypt library (-lcrypt).  */
#define HAVE_LIBCRYPT 1

/* Define if you have the dgc library (-ldgc).  */
/* #undef HAVE_LIBDGC */

/* Define if you have the i library (-li).  */
/* #undef HAVE_LIBI */

/* Define if you have the kstat library (-lkstat).  */
/* #undef HAVE_LIBKSTAT */

/* Define if you have the os library (-los).  */
/* #undef HAVE_LIBOS */

/* Define if you have the sec library (-lsec).  */
/* #undef HAVE_LIBSEC */

/* Define if you have the shadow library (-lshadow).  */
/* #undef HAVE_LIBSHADOW */

/* Define if you have the sun library (-lsun).  */
/* #undef HAVE_LIBSUN */

/* Define if you have the ypsec library (-lypsec).  */
/* #undef HAVE_LIBYPSEC */
