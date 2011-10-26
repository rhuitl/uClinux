/* stdlib.h  <ndf@linux.mit.edu> */
#include <features.h>
#include <alloca.h>
#include <sys/types.h>

#ifndef __STDLIB_H
#define __STDLIB_H

__BEGIN_DECLS

/* Don't overwrite user definitions of NULL */
#ifndef NULL
#define NULL ((void *) 0)
#endif

#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif /*!RAND_MAX*/

/* For program termination */
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

extern void * malloc __P ((size_t));
extern void * calloc __P ((size_t, size_t));
extern void free __P ((void *));
extern void * realloc __P ((void *, size_t));

#ifdef DEBUG_MALLOC

extern void * malloc_dbg __P ((size_t, char* func, char* file, int line));
extern void * calloc_dbg __P ((size_t, size_t, char* func, char* file, int line));
extern void free_dbg __P ((void *, char* func, char* file, int line));
extern void * realloc_dbg __P ((void *, size_t, char* func, char* file, int line));

#define malloc(x) malloc_dbg((x),__FUNCTION__,__FILE__,__LINE__)
#define calloc(x,y) calloc_dbg((x),(y),__FUNCTION__,__FILE__,__LINE__)
#define free(x) free_dbg((x),__FUNCTION__,__FILE__,__LINE__)
#define realloc(x) realloc((x),__FUNCTION__,__FILE__,__LINE__)

#endif

extern int rand __P ((void));
extern void srand __P ((unsigned int seed));
extern void srandom __P ((unsigned int seed));
extern long random __P ((void));

extern long strtol __P ((const char * nptr, char ** endptr, int base));
extern unsigned long strtoul __P ((const char * nptr,
				   char ** endptr, int base));

#define strtoull(a,b,c) ((unsigned long long) strtol(a,b,c))

#ifndef __HAS_NO_FLOATS__
extern double strtod __P ((const char * nptr, char ** endptr));
#endif

extern char *getenv __P ((__const char *__name));

extern int putenv __P ((__const char *__string));

extern int setenv __P ((__const char *__name, __const char *__value,
                        int __replace));
extern void unsetenv __P ((__const char *__name));

extern int system __P ((__const char *__command));

extern void qsort __P ((void *base, int num, int size, int (*cmp)(__const void *, __const void *)));
extern void *bsearch __P ((__const void *key, __const void *base, size_t nmemb,
				size_t size, int (*compar)(__const void *, __const void *)));
extern char * gcvt __P ((double number, size_t ndigit, char * buf));

#define atof(x) strtod((x),(char**)0)

/* Returned by `div'.  */
typedef struct
  {
    int quot;			/* Quotient.  */
    int rem;			/* Remainder.  */
  } div_t;

/* Returned by `ldiv'.  */
typedef struct
  {
    long int quot;		/* Quotient.  */
    long int rem;		/* Remainder.  */
  } ldiv_t;

extern void exit __P ((int __status)) __attribute__ ((__noreturn__));
extern int atexit __P ((void (*function)(void)));
extern int system __P ((__const char *__command));
extern int abs __P ((int __x)) __attribute__ ((__const__));
extern int atoi __P ((__const char *__nptr));
extern long atol __P ((__const char *__nptr));
extern long long atoll __P ((__const char *__nptr));

extern void abort __P((void)) __attribute__ ((__noreturn__));

extern int mkstemp __P ((char * __template));
extern char * mktemp __P ((char * __template));

extern char *realpath __P ((__const char *__restrict __name,
			 	char *__restrict __resolved));
__END_DECLS

#endif /* __STDLIB_H */
