/* dnsmasq is Copyright (c) 2000 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* Author's email: simon@thekelleys.org.uk */

#define VERSION "1.18"

#define FTABSIZ 150 /* max number of outstanding requests */
#define TIMEOUT 40 /* drop queries after TIMEOUT seconds */
#define LOGRATE 120 /* log table overflows every LOGRATE seconds */
#ifdef EMBED
#define CACHESIZ 100 /* default cache size */
#else
#define CACHESIZ 150 /* default cache size */
#endif
#define MAXTOK 50 /* token in DHCP leases */
#define SMALLDNAME 40 /* most domain names are smaller than this */

#ifndef ETC_DIR
#define ETC_DIR "/etc"
#endif
#define CONFFILE ETC_DIR "/dnsmasq.conf"
#define HOSTSFILE ETC_DIR "/hosts"
#define RESOLVFILE ETC_DIR "/resolv.conf"

#define RUNFILE "/var/run/dnsmasq.pid"
#define CHUSER "nobody"
#define CHGRP "dip"
#define IP6INTERFACES "/proc/net/if_inet6"

/* Logfile stuff - change this to change the options and facility */
/* debug is true if the --no-daemon flag is given */
#ifdef LOG_PERROR
#  define DNSMASQ_LOG_OPT(debug)  (debug) ? LOG_PERROR : LOG_PID
#else
#  define DNSMASQ_LOG_OPT(debug)  (debug) ? 0 : LOG_PID
#endif

#ifdef LOG_LOCAL0
#  define DNSMASQ_LOG_FAC(debug)  (debug) ? LOG_LOCAL0 : LOG_DAEMON
#else
#  define DNSMASQ_LOG_FAC(debug)  LOG_DAEMON
#endif


/* Decide if we're going to support IPv6 */
/* We assume that systems which don't have IPv6
   headers don't have ntop and pton either */
#ifdef EMBED
# ifdef HAVE_IPV6
#   define ADDRSTRLEN INET6_ADDRSTRLEN
# else
#   define ADDRSTRLEN INET_ADDRSTRLEN
# endif
#else
#if defined(INET6_ADDRSTRLEN)
#  define HAVE_IPV6
#  define ADDRSTRLEN INET6_ADDRSTRLEN
#elif defined(INET_ADDRSTRLEN)
#  undef HAVE_IPV6
#  define ADDRSTRLEN INET_ADDRSTRLEN
#else
#  undef HAVE_IPV6
#  define ADDRSTRLEN 16 /* 4*3 + 3 dots + NULL */
#endif
#endif

/* Get linux C library versions. */
#if defined(__linux__) && !defined(__UCLIBC__) && !defined(__uClinux__)
#  include <libio.h> 
#endif


/* Follows system specific switches. If you run on a 
   new system, you may want to edit these. 
   May replace this with Autoconf one day. 


HAVE_LINUX_IPV6_PROC
   define this to do IPv6 interface discovery using
   proc/net/if_inet6 ala LINUX. 

HAVE_GETOPT_LONG
   define this if you have GNU libc or GNU getopt. 

HAVE_ARC4RANDOM
   define this if you have arc4random() to get better security from DNS spoofs
   by using really random ids (OpenBSD) 

HAVE_RANDOM
   define this if you have the 4.2BSD random() function (and its
   associated srandom() function), which is at least as good as (if not
   better than) the rand() function.

HAVE_DEV_RANDOM
   define this if you have the /dev/random device, which gives truly
   random numbers but may run out of random numbers.

HAVE_DEV_URANDOM
   define this if you have the /dev/urandom device, which gives
   semi-random numbers when it runs out of truly random numbers.

HAVE_SOCKADDR_SA_LEN
   define this if struct sockaddr has sa_len field (*BSD) 

NOTES:
   For Linux you should define 
      HAVE_LINUX_IPV6_PROC 
      HAVE_GETOPT_LONG
      HAVE_RANDOM
      HAVE_DEV_RANDOM
      HAVE_DEV_URANDOM
   you should NOT define 
      HAVE_ARC4RANDOM
      HAVE_SOCKADDR_SA_LEN

   For *BSD systems you should define 
     HAVE_SOCKADDR_SA_LEN
     HAVE_RANDOM
   you should NOT define  
     HAVE_LINUX_IPV6_PROC 
   and you MAY define  
     HAVE_ARC4RANDOM - OpenBSD and FreeBSD 
     HAVE_DEV_URANDOM - OpenBSD and FreeBSD
     HAVE_DEV_RANDOM - FreeBSD (OpenBSD with hardware random number generator)
     HAVE_GETOPT_LONG - only if you link GNU getopt. 

*/

/* Must preceed __linux__ since uClinux defines __linux__ too. */
#if defined(__uClinux__) || defined(__UCLIBC__)
#undef HAVE_LINUX_IPV6_PROC
#define HAVE_GETOPT_LONG
#undef HAVE_ARC4RANDOM
#define HAVE_RANDOM
#define HAVE_DEV_URANDOM
#define HAVE_DEV_RANDOM
#undef HAVE_SOCKADDR_SA_LEN
/* Don't fork into background on uClinux */
#if defined(__uClinux__)
#  define NO_FORK
#endif

/* libc5 - must precede __linux__ too */
/* Note to build a libc5 binary on a modern Debian system:
   install the packages altgcc libc5 and libc5-altdev 
   then run "make CC=i486-linuxlibc1-gcc" */
#elif defined(__linux__) && \
      defined(_LINUX_C_LIB_VERSION_MAJOR) && \
      (_LINUX_C_LIB_VERSION_MAJOR == 5 )
#undef HAVE_IPV6
#undef HAVE_LINUX_IPV6_PROC
#define HAVE_GETOPT_LONG
#undef HAVE_ARC4RANDOM
#define HAVE_RANDOM
#define HAVE_DEV_URANDOM
#define HAVE_DEV_RANDOM
#undef HAVE_SOCKADDR_SA_LEN
/* Fix various misfeatures of libc5 headers */
#define T_SRV 33 
typedef unsigned long in_addr_t; 
typedef size_t socklen_t;

/* This is for glibc 2.x */
#elif defined(__linux__)
#define HAVE_LINUX_IPV6_PROC
#define HAVE_GETOPT_LONG
#undef HAVE_ARC4RANDOM
#define HAVE_RANDOM
#define HAVE_DEV_URANDOM
#define HAVE_DEV_RANDOM
#undef HAVE_SOCKADDR_SA_LEN
/* glibc < 2.2  has broken Sockaddr_in6 so we have to use our own. */
/* glibc < 2.2 doesn't define in_addr_t */
#if defined(__GLIBC__) && (__GLIBC__ == 2) && \
    defined(__GLIBC_MINOR__) && (__GLIBC_MINOR__ < 2)
typedef unsigned long in_addr_t; 
#if defined(HAVE_IPV6)
#   define HAVE_BROKEN_SOCKADDR_IN6
#endif
#endif

#elif defined(__FreeBSD__) || defined(__OpenBSD__)
#undef HAVE_LINUX_IPV6_PROC
#undef HAVE_GETOPT_LONG
#define HAVE_ARC4RANDOM
#define HAVE_RANDOM
#define HAVE_DEV_URANDOM
#define HAVE_SOCKADDR_SA_LEN

#elif defined(__APPLE__)
#undef HAVE_LINUX_IPV6_PROC
#undef HAVE_GETOPT_LONG
#define HAVE_ARC4RANDOM
#define HAVE_RANDOM
#define HAVE_DEV_URANDOM
#define HAVE_SOCKADDR_SA_LEN
/* Define before sys/socket.h is included so we get socklen_t */
#define _BSD_SOCKLEN_T_
/* The two below are not defined in Mac OS X arpa/nameserv.h */
#define IN6ADDRSZ 16
#define T_SRV 33
 
#elif defined(__NetBSD__)
#undef HAVE_LINUX_IPV6_PROC
#undef HAVE_GETOPT_LONG
#undef HAVE_ARC4RANDOM
#define HAVE_RANDOM
#undef HAVE_DEV_URANDOM
#undef HAVE_DEV_RANDOM
#define HAVE_SOCKADDR_SA_LEN
 
/* env "LIBS=-lsocket -lnsl" make */
#elif defined(__sun) || defined(__sun__)
#undef HAVE_LINUX_IPV6_PROC
#undef HAVE_GETOPT_LONG
#undef HAVE_ARC4RANDOM
#define HAVE_RANDOM
#undef HAVE_DEV_URANDOM
#undef HAVE_DEV_RANDOM
#undef HAVE_SOCKADDR_SA_LEN
#endif



