/* port.h - portability defines */

#if defined(__FreeBSD__)
# define FreeBSD
# define ARCH "FreeBSD"
#else
# if defined(linux)
#  define Linux
#  define ARCH "Linux"
# else
#  if defined(sun)
#   define Solaris
#   define ARCH "Solaris"
#  else
#   define UNKNOWN
#   define ARCH "UNKNOWN"
#  endif
# endif
#endif

#ifdef FreeBSD
# define HAVE_DAEMON
# define HAVE_SETSID
# define HAVE_SETLOGIN
# define HAVE_WAITPID
# define HAVE_HSTRERROR
# define HAVE_TM_GMTOFF
#endif

#ifdef Linux
# ifndef __uClinux__
#  define HAVE_DAEMON
# endif
# define HAVE_SETSID
# define HAVE_WAITPID
#endif

#ifdef Solaris
# define HAVE_SETSID
# define HAVE_WAITPID
# define HAVE_MEMORY_H
#endif

#ifdef USE_IPV6
# define HAVE_SOCKADDR_IN6
# define HAVE_SOCKADDR_STORAGE
# define HAVE_GETADDRINFO
# define HAVE_GETNAMEINFO
# define HAVE_GAI_STRERROR
#endif
