/* nstd.h */

/* Never Standard.h

   This has all the prototypes that are supposed to
   be in a standard place but never are, and when they are
   the standard place isn't standard
*/

/*
$Log: nstd.h,v $
 * Revision 1.6  1995/06/18  19:42:22  mike
 * Remove some redundant declarations and add some prototypes
 *
 * Revision 1.5  1995/04/20  20:26:56  mike
 * beta improvements from Carl Mascott
 *
 * Revision 1.4  1994/12/11  22:08:24  mike
 * add STDC_MATHERR
 *
 * Revision 1.3  1993/07/15  23:56:09  mike
 * general cleanup
 *
 * Revision 1.2  1993/07/07  00:07:43  mike
 * more work on 1.2
 *
 * Revision 1.1  1993/07/04  12:38:06  mike
 * Initial revision
 *
*/

#ifndef  NSTD_H
#define  NSTD_H		1

#include "config.h"

#ifdef   NO_PROTOS
#define  PROTO(name,args)	name()
#else
#define  PROTO(name,args)	name args
#endif



/* types */

#ifdef  NO_VOID_STAR
typedef  char *PTR ;
#else
typedef  void *PTR ;
#endif

#ifdef   SIZE_T_STDDEF_H
#include <stddef.h>
#else
#ifdef   SIZE_T_TYPES_H
#include <sys/types.h>
#else
typedef  unsigned  size_t ;
#endif
#endif

/* stdlib.h */

double  PROTO(strtod, (const char*, char**)) ;
void    PROTO(free, (void*)) ;
PTR     PROTO(malloc, (size_t)) ;
PTR     PROTO(realloc, (void*,size_t)) ;
void    PROTO(exit, (int)) ;
char*   PROTO(getenv, (const char*)) ;

/* string.h */

int	PROTO(memcmp, (const void*,const void*,size_t)) ;
PTR	PROTO(memcpy, (void*,const void*,size_t)) ;
PTR	PROTO(memset, (void*,int,size_t)) ;
char*	PROTO(strchr, (const char*, int)) ;
int	PROTO(strcmp, (const char*,const char*)) ;
char*	PROTO(strcpy, (char *, const char*)) ;
size_t	PROTO(strlen, (const char*)) ;
int  	PROTO(strncmp, (const char*,const char*,size_t)) ;
char*	PROTO(strncpy, (char*, const char*, size_t)) ;
char*   PROTO(strrchr, (const char*,int)) ;
char*	PROTO(strerror, (int)) ;


#ifdef  NO_ERRNO_H
extern  int errno ;
#else
#include <errno.h>
#endif

/* math.h */
double  PROTO(fmod,(double,double)) ;

/* if have to diddle with errno to get errors from the math library */
#ifndef STDC_MATHERR
#define STDC_MATHERR   (FPE_TRAPS_ON && NO_MATHERR)
#endif

#endif  /* NSTD_H */

