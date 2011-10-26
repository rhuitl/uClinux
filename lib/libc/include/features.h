
#ifndef __FEATURES_H
#define __FEATURES_H


/* Major and minor version number of the uClibc library package.  Use
   these macros to test for features in specific releases.  */
#define __UC_LIBC__             0 /* so we can detect old uC-libc easily */
#define __UCLIBC__              0
#define __UCLIBC_MAJOR__        9
#define __UCLIBC_MINOR__        1

#ifdef __STDC__

#define __P(x) x
#define __const const

/* Almost ansi */
#if __STDC__ != 1
#define const
#define volatile
#endif

#else /* K&R */

#define __P(x) ()
#define __const
#define const
#define volatile

#endif

/* C++ needs to know that types and declarations are C, not C++.  */
#ifdef	__cplusplus
# define __BEGIN_DECLS	extern "C" {
# define __END_DECLS	}
#else
# define __BEGIN_DECLS
# define __END_DECLS
#endif

/* GNUish things */
#define __CONSTVALUE
#define __CONSTVALUE2

#define _POSIX_THREAD_SAFE_FUNCTIONS

#ifdef _GNU_SOURCE
# define __USE_GNU	1
#endif

#include <sys/cdefs.h>


#endif

