
#ifndef __SYS_CDEFS_H
#define __SYS_CDEFS_H
#include <features.h>

#if defined (__STDC__) && __STDC__

#define	__CONCAT(x,y)	x ## y
#define	__STRING(x)	#x

/* This is not a typedef so `const __ptr_t' does the right thing.  */
#define __ptr_t void *
typedef long double __long_double_t;

#else

#define	__CONCAT(x,y)	x/**/y
#define	__STRING(x)	"x"

#define __ptr_t char *

#ifndef __HAS_NO_FLOATS__
typedef double __long_double_t;
#endif

#endif

/* C++ needs to know that types and declarations are C, not C++.  */
#ifdef	__cplusplus
# define __THROW	throw ()
# define __BEGIN_DECLS	extern "C" {
# define __END_DECLS	}
#else
# define __THROW
# define __BEGIN_DECLS
# define __END_DECLS
#endif

/* GNUish things */
#define __CONSTVALUE
#define __CONSTVALUE2

#endif
